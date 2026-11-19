// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package restartfence

import (
	"cmp"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
)

// MaxPodMembers is the v3 snapshot capacity, not a truncation limit. A
// publisher exceeding it must leave the old row and product state intact.
const MaxPodMembers = 128

const podInactive = 1

var ErrStalePod = errors.New("stale exec fence pod revision or identity")

// PodRef identifies one exact revision of the host pod's classification.
// Serialize product transitions with the receipt; rereading a new receipt
// does not authorize replaying an old product attestation.
type PodRef struct {
	ID       uint64
	UIDHash  uint64
	Revision uint64
}

// ChildRef identifies a specific container cgroup and binding identity.
type ChildRef struct {
	ID       uint64
	Identity uint64
}

// PodMember describes the compiled class for an attested host container
// cgroup, or Off for an authoritatively unselected sibling. The caller keeps
// the cgroup descriptors open throughout PublishCensus.
type PodMember struct {
	Cgroup   *os.File
	Identity uint64
	Mode     Mode
}

// ChildState is the published classification, not a product readiness claim.
type ChildState struct {
	ChildRef
	Mode                 Mode
	Owner                uint64
	Generation           uint64
	AccountedIncarnation uint64
}

type PodState struct {
	PodRef
	Fallback                     Mode
	Inactive                     bool
	Children                     []ChildState
	FallbackAccountedIncarnation uint64
}

type podChild struct {
	CgroupID             uint64
	Identity             uint64
	Owner                uint64
	Generation           uint64
	StrictSections       uint32
	AuditSections        uint32
	OffSections          uint32
	BoundSections        uint32
	AccountedIncarnation uint64
	Reserved             [1]uint64
}

type podRow struct {
	UIDHash                      uint64
	Revision                     uint64
	StrictSections               uint32
	AuditSections                uint32
	ChildCount                   uint32
	Flags                        uint32
	FallbackAccountedIncarnation uint64
	Reserved                     [3]uint64
	Children                     [MaxPodMembers]podChild
}

func childMode(c podChild) Mode {
	switch {
	case c.StrictSections == execSection && c.AuditSections == 0 && c.OffSections == 0:
		return Strict
	case c.StrictSections == 0 && c.AuditSections == execSection && c.OffSections == 0:
		return Audit
	case c.StrictSections == 0 && c.AuditSections == 0 && c.OffSections == execSection:
		return Off
	default:
		return 0
	}
}

func newPodChild(id, identity uint64, mode Mode) (podChild, error) {
	if id == 0 || identity == 0 {
		return podChild{}, fmt.Errorf("zero container cgroup or binding identity")
	}
	entry := podChild{CgroupID: id, Identity: identity}
	switch mode {
	case Strict:
		entry.StrictSections = execSection
	case Audit:
		entry.AuditSections = execSection
	case Off:
		entry.OffSections = execSection
	default:
		return podChild{}, fmt.Errorf("invalid child exec mode %d", mode)
	}
	return entry, nil
}

func podFallback(row *podRow) Mode {
	switch {
	case row.StrictSections == execSection && row.AuditSections == 0:
		return Strict
	case row.StrictSections == 0 && row.AuditSections == execSection:
		return Audit
	default:
		return 0
	}
}

func verifyPodRow(row *podRow) error {
	if row.UIDHash == 0 || row.Revision == 0 || row.ChildCount > MaxPodMembers || row.Reserved != [3]uint64{} {
		return fmt.Errorf("invalid exec fence pod row")
	}
	if row.Flags == podInactive {
		if row.ChildCount == 0 && row.StrictSections|row.AuditSections == 0 && row.FallbackAccountedIncarnation == 0 && row.Children == [MaxPodMembers]podChild{} {
			return nil
		}
		return fmt.Errorf("invalid inactive pod row")
	}
	fallback := podFallback(row)
	if row.Flags != 0 || fallback == 0 || !validAccountingIncarnation(row.FallbackAccountedIncarnation) {
		return fmt.Errorf("invalid marked-pod fallback mode")
	}
	var previous uint64
	for _, c := range row.Children[:row.ChildCount] {
		mode := childMode(c)
		if c.CgroupID <= previous || c.Identity == 0 || mode == 0 || (fallback == Audit && mode == Strict) || c.Reserved != [1]uint64{} {
			return fmt.Errorf("invalid or inconsistent child classification")
		}
		if mode == Off && c.AccountedIncarnation != 0 || mode != Off && !validAccountingIncarnation(c.AccountedIncarnation) {
			return fmt.Errorf("invalid child accounting incarnation")
		}
		switch c.BoundSections {
		case 0:
			if c.Owner != 0 || c.Generation != 0 {
				return fmt.Errorf("unattested child owner or generation")
			}
		case execSection:
			if mode == Off || c.Owner == 0 || c.Owner == retired || c.Generation == 0 || c.AccountedIncarnation != c.Owner {
				return fmt.Errorf("invalid child handover")
			}
		default:
			return fmt.Errorf("unsupported child handover section")
		}
		previous = c.CgroupID
	}
	for _, unused := range row.Children[row.ChildCount:] {
		if unused != (podChild{}) {
			return fmt.Errorf("nonzero unused exec fence child")
		}
	}
	return nil
}

func validAccountingIncarnation(epoch uint64) bool {
	return epoch != 0 && epoch != retired
}

// verifyPodAccounting also rejects provenance newer than the last issued owner.
// It never repairs or normalizes an incompatible row.
func verifyPodAccounting(row *podRow, issued uint64) error {
	if err := verifyPodRow(row); err != nil {
		return err
	}
	if row.FallbackAccountedIncarnation > issued {
		return fmt.Errorf("future pod accounting incarnation")
	}
	for _, child := range row.Children[:row.ChildCount] {
		if child.AccountedIncarnation > issued {
			return fmt.Errorf("future child accounting incarnation")
		}
	}
	return nil
}

func verifyStoredPodAccounting(id uint64, row *podRow, issued uint64) error {
	if id == 0 {
		return fmt.Errorf("zero fence pod inventory key")
	}
	if err := verifyPodAccounting(row, issued); err != nil {
		return err
	}
	for _, child := range row.Children[:row.ChildCount] {
		if child.CgroupID == id {
			return fmt.Errorf("fence pod contains itself as a child")
		}
	}
	return nil
}

func cgroupFDPath(f *os.File) (string, error) {
	conn, err := f.SyscallConn()
	if err != nil {
		return "", err
	}
	var path string
	var lookupErr error
	err = conn.Control(func(fd uintptr) {
		path, lookupErr = os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	})
	if err := errors.Join(err, lookupErr); err != nil {
		return "", err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasSuffix(path, " (deleted)") {
		return "", fmt.Errorf("unresolved host cgroup path")
	}
	return path, nil
}

func publishableMembers(podID uint64, podMount int, podPath string, members []PodMember) ([]podChild, error) {
	if len(members) > MaxPodMembers {
		return nil, fmt.Errorf("exec fence pod census exceeds %d members", MaxPodMembers)
	}
	rows := make([]podChild, 0, len(members))
	for _, member := range members {
		id, mount, err := hostCgroupID(member.Cgroup)
		if err != nil {
			return nil, err
		}
		if id == podID || mount != podMount {
			return nil, fmt.Errorf("container %d is not in the pod's host cgroup mount", id)
		}
		path, err := cgroupFDPath(member.Cgroup)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(podPath, path)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
			return nil, fmt.Errorf("container %d is not inside the pod cgroup", id)
		}
		row, err := newPodChild(id, member.Identity, member.Mode)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b podChild) int { return cmp.Compare(a.CgroupID, b.CgroupID) })
	for i := 1; i < len(rows); i++ {
		if rows[i-1].CgroupID == rows[i].CgroupID {
			return nil, fmt.Errorf("duplicate container cgroup ID %d", rows[i].CgroupID)
		}
	}
	return rows, nil
}

func podLookup(p *pinnedFence, id uint64) (podRow, bool, error) {
	var row podRow
	err := p.maps["fence_cgroups"].Lookup(id, &row)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return podRow{}, false, nil
	}
	if err != nil {
		return podRow{}, false, err
	}
	owner, err := readOwner(p)
	if err != nil {
		return podRow{}, false, err
	}
	if err := verifyStoredPodAccounting(id, &row, owner.Incarnation); err != nil {
		return podRow{}, false, err
	}
	return row, true, nil
}

func (row *podRow) ref(id uint64) PodRef {
	return PodRef{ID: id, UIDHash: row.UIDHash, Revision: row.Revision}
}

func (row *podRow) child(ref ChildRef) (*podChild, error) {
	i, ok := slices.BinarySearchFunc(row.Children[:row.ChildCount], ref.ID, func(c podChild, id uint64) int {
		return cmp.Compare(c.CgroupID, id)
	})
	if !ok || row.Children[i].Identity != ref.Identity {
		return nil, ErrStalePod
	}
	return &row.Children[i], nil
}

func mergeCensus(row *podRow, added []podChild, fallback Mode, incarnation uint64) error {
	if !validAccountingIncarnation(incarnation) {
		return fmt.Errorf("invalid census accounting incarnation")
	}
	// Added candidates are newly classified but not handed over. Existing rows
	// win the merge and retain their own provenance.
	added = slices.Clone(added)
	for i := range added {
		if childMode(added[i]) != Off {
			added[i].AccountedIncarnation = incarnation
		}
	}
	if fallback != Strict && fallback != Audit {
		return fmt.Errorf("unsupported pod fallback mode %d", fallback)
	}
	old := row.Children[:row.ChildCount]
	result := make([]podChild, 0, min(MaxPodMembers, len(old)+len(added)))
	for len(old) != 0 || len(added) != 0 {
		if len(result) == MaxPodMembers {
			return fmt.Errorf("exec fence pod census exceeds %d members", MaxPodMembers)
		}
		switch {
		case len(added) == 0 || len(old) != 0 && old[0].CgroupID < added[0].CgroupID:
			result = append(result, old[0])
			old = old[1:]
		case len(old) == 0 || added[0].CgroupID < old[0].CgroupID:
			result = append(result, added[0])
			added = added[1:]
		default:
			current, wanted := old[0], added[0]
			if current.Identity != wanted.Identity {
				return ErrStalePod
			}
			if childMode(current) != childMode(wanted) {
				if childMode(current) != Off {
					return fmt.Errorf("cgroup %d classification must retain last-good mode until explicit committed withdrawal", current.CgroupID)
				}
				current = wanted
			}
			result = append(result, current)
			old, added = old[1:], added[1:]
		}
	}
	// A conservative fallback change cannot silently drop an existing Strict
	// child or treat possibly Strict unknown children as Audit.
	for _, child := range result {
		if fallback == Audit && childMode(child) == Strict {
			return fmt.Errorf("audit fallback would hide a retained Strict classification")
		}
	}
	if row.Revision == 0 || row.Flags == podInactive {
		row.FallbackAccountedIncarnation = incarnation
	}
	row.Flags, row.StrictSections, row.AuditSections = 0, 0, 0
	if fallback == Audit {
		row.AuditSections = execSection
	} else {
		row.StrictSections = execSection
	}
	row.ChildCount = uint32(len(result))
	clear(row.Children[:])
	copy(row.Children[:], result)
	return nil
}

func publishPod(p *pinnedFence, id uint64, previous, row *podRow) (PodRef, error) {
	if *row == *previous {
		return row.ref(id), nil
	}
	if previous.Revision == math.MaxUint64 {
		return PodRef{}, fmt.Errorf("exec fence pod revision exhausted")
	}
	row.Revision = previous.Revision + 1
	owner, err := readOwner(p)
	if err != nil {
		return PodRef{}, err
	}
	if err := verifyStoredPodAccounting(id, row, owner.Incarnation); err != nil {
		return PodRef{}, err
	}
	if err := p.maps["fence_cgroups"].Put(id, row); err != nil {
		return PodRef{}, err
	}
	return row.ref(id), nil
}

// PublishCensus establishes the pod mark and the known classifications in a
// single hash update, without releasing any newly managed child. An Audit
// fallback requires authoritative proof that no Strict child can be selected.
// Omission is never withdrawal authority; previous rows are retained.
func (f *Fence) PublishCensus(pod *os.File, uidHash, expectedRevision uint64, fallback Mode, members []PodMember) (PodRef, error) {
	id, mount, err := hostCgroupID(pod)
	if err != nil {
		return PodRef{}, err
	}
	if uidHash == 0 {
		return PodRef{}, fmt.Errorf("zero pod UID fingerprint")
	}
	path, err := cgroupFDPath(pod)
	if err != nil {
		return PodRef{}, err
	}
	rows, err := publishableMembers(id, mount, path, members)
	if err != nil {
		return PodRef{}, err
	}
	var result PodRef
	err = f.ownerAction(func(p *pinnedFence) error {
		old, exists, err := podLookup(p, id)
		if err != nil {
			return err
		}
		if old.Revision != expectedRevision || (exists && old.UIDHash != uidHash) {
			return ErrStalePod
		}
		next := old
		next.UIDHash = uidHash
		if err := mergeCensus(&next, rows, fallback, f.incarnation); err != nil {
			return err
		}
		if err := initTotals(p, id); err != nil {
			return err
		}
		result, err = publishPod(p, id, &old, &next)
		return err
	})
	return result, err
}

func (f *Fence) mutatePod(ref PodRef, operation func(*podRow) error) (PodRef, error) {
	var result PodRef
	err := f.ownerAction(func(p *pinnedFence) error {
		old, exists, err := podLookup(p, ref.ID)
		if err != nil {
			return err
		}
		if !exists || old.ref(ref.ID) != ref {
			return ErrStalePod
		}
		next := old
		if err := operation(&next); err != nil {
			return err
		}
		result, err = publishPod(p, ref.ID, &old, &next)
		return err
	})
	return result, err
}

func (f *Fence) mutateChild(ref PodRef, id ChildRef, operation func(*podChild) error) (PodRef, error) {
	return f.mutatePod(ref, func(row *podRow) error {
		child, err := row.child(id)
		if err != nil {
			return err
		}
		return operation(child)
	})
}

// RefenceChild must finish before a product operation can weaken protection.
func (f *Fence) RefenceChild(pod PodRef, child ChildRef) (PodRef, error) {
	return f.mutateChild(pod, child, refencePodChild)
}

// MoveChild releases only the given child. The caller must freshly attest the
// exact product identity and committed generation and serialize the operation
// with future publication/withdrawal. A stale pod receipt cannot be replayed.
func (f *Fence) MoveChild(pod PodRef, child ChildRef, generation uint64) (PodRef, error) {
	if generation == 0 {
		return PodRef{}, fmt.Errorf("unattested exec generation")
	}
	return f.mutateChild(pod, child, func(entry *podChild) error {
		return movePodChild(entry, f.incarnation, generation)
	})
}

// CommitPolicyWithdrawal requires an authoritative policy removal and product
// route withdrawal already committed; failed or uncertain discovery is not
// authority. RefenceChild must have preceded removal.
func (f *Fence) CommitPolicyWithdrawal(pod PodRef, child ChildRef) (PodRef, error) {
	return f.mutateChild(pod, child, withdrawPodChild)
}

func refencePodChild(entry *podChild) error {
	entry.BoundSections, entry.Owner, entry.Generation = 0, 0, 0
	// Keep attribution even when a successor refences an already-unbound row.
	return nil
}

func movePodChild(entry *podChild, incarnation, generation uint64) error {
	if childMode(*entry) == Off {
		return fmt.Errorf("handover requires a managed child")
	}
	if !validAccountingIncarnation(incarnation) || generation == 0 {
		return fmt.Errorf("unattested exec generation or incarnation")
	}
	entry.BoundSections, entry.Owner, entry.Generation = execSection, incarnation, generation
	entry.AccountedIncarnation = incarnation
	return nil
}

func withdrawPodChild(entry *podChild) error {
	if entry.BoundSections != 0 {
		return fmt.Errorf("publishing Off requires a refenced child")
	}
	entry.StrictSections, entry.AuditSections, entry.OffSections = 0, 0, execSection
	entry.AccountedIncarnation = 0
	return nil
}

// DeactivateExecScope is for authoritative removal of every potentially
// selecting exec policy for this pod. Zero current children alone is not
// authority. Preserve a tombstone so stale publish receipts cannot return.
func (f *Fence) DeactivateExecScope(ref PodRef) (PodRef, error) {
	return f.mutatePod(ref, func(row *podRow) error {
		for _, child := range row.Children[:row.ChildCount] {
			if childMode(child) != Off {
				return fmt.Errorf("pod still contains a managed exec child")
			}
		}
		row.Flags, row.StrictSections, row.AuditSections, row.ChildCount = podInactive, 0, 0, 0
		row.FallbackAccountedIncarnation = 0
		clear(row.Children[:])
		return nil
	})
}

// AcknowledgePodAccounting attributes fallback observations to the current
// incarnation only after the caller proves a complete current pod/policy census
// with no ambiguous identities and settles every retained managed child. The
// caller serializes that proof with native mutations and uses the returned ref.
// This changes accounting, never classification or native readiness.
func (f *Fence) AcknowledgePodAccounting(ref PodRef) (PodRef, error) {
	return f.mutatePod(ref, func(row *podRow) error {
		return acknowledgePodAccounting(row, f.incarnation)
	})
}

func acknowledgePodAccounting(row *podRow, incarnation uint64) error {
	if !validAccountingIncarnation(incarnation) {
		return fmt.Errorf("invalid accounting acknowledgment incarnation")
	}
	if err := verifyPodAccounting(row, incarnation); err != nil {
		return err
	}
	if row.Flags == podInactive {
		return nil
	}
	for _, child := range row.Children[:row.ChildCount] {
		if childMode(child) != Off && (child.BoundSections != execSection ||
			child.Owner != incarnation || child.Generation == 0 || child.AccountedIncarnation != incarnation) {
			return fmt.Errorf("pod accounting recovery has unsettled managed children")
		}
	}
	row.FallbackAccountedIncarnation = incarnation
	return nil
}

// RemoveExitedChild requires independent proof that this physical host
// container cgroup is gone. Mere discovery loss is insufficient.
func (f *Fence) RemoveExitedChild(ref PodRef, child ChildRef) (PodRef, error) {
	return f.mutatePod(ref, func(row *podRow) error {
		i, found := slices.BinarySearchFunc(row.Children[:row.ChildCount], child.ID, func(entry podChild, id uint64) int {
			return cmp.Compare(entry.CgroupID, id)
		})
		if !found || row.Children[i].Identity != child.Identity {
			return ErrStalePod
		}
		rows := row.Children[:row.ChildCount]
		copy(rows[i:], rows[i+1:])
		rows[len(rows)-1] = podChild{}
		row.ChildCount--
		return nil
	})
}

// RemoveExited requires proof that this physical pod cgroup is gone. No
// current policy, discovery failure or shutdown is authorization to remove it.
func (f *Fence) RemoveExited(ref PodRef) error {
	return f.ownerAction(func(p *pinnedFence) error {
		row, exists, err := podLookup(p, ref.ID)
		if err != nil {
			return err
		}
		if !exists || row.ref(ref.ID) != ref {
			return ErrStalePod
		}
		if err := p.maps["fence_cgroups"].Delete(ref.ID); err != nil {
			return err
		}
		err = p.maps["fence_counts"].Delete(ref.ID)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	})
}

// RemoveExitedOrphanCounters reclaims counter-only residue from interrupted
// publication or removal. The caller must independently prove that this full
// physical host pod cgroup ID has exited; discovery loss is not proof. The row
// absence check and counter deletion share the owner lock, so publication cannot
// race the check. Existing rows (including inactive rows) retain their telemetry.
func (f *Fence) RemoveExitedOrphanCounters(podID uint64) error {
	if podID == 0 {
		return fmt.Errorf("infrastructure counters cannot be reclaimed")
	}
	return f.ownerAction(func(p *pinnedFence) error {
		return removeExitedOrphanCounters(podID, func(id uint64) (bool, error) {
			_, exists, err := podLookup(p, id)
			return exists, err
		}, func(id uint64) error { return p.maps["fence_counts"].Delete(id) })
	})
}

// The caller holds the owner lock for this entire check-and-delete operation.
func removeExitedOrphanCounters(podID uint64, rowExists func(uint64) (bool, error), deleteCounters func(uint64) error) error {
	if podID == 0 {
		return fmt.Errorf("infrastructure counters cannot be reclaimed")
	}
	exists, err := rowExists(podID)
	if err != nil {
		return err
	}
	if exists {
		return ErrStalePod
	}
	err = deleteCounters(podID)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// ReadPod reports the current classification receipt. It does not change
// pins, decide Kubernetes selection, or attest product protection.
func (f *Fence) ReadPod(id uint64) (PodState, bool, error) {
	var result PodState
	var exists bool
	err := f.locked(func(p *pinnedFence) error {
		row, found, err := podLookup(p, id)
		exists = found
		if err != nil || !found {
			return err
		}
		result = PodState{PodRef: row.ref(id), Fallback: podFallback(&row), Inactive: row.Flags == podInactive, FallbackAccountedIncarnation: row.FallbackAccountedIncarnation}
		for _, entry := range row.Children[:row.ChildCount] {
			result.Children = append(result.Children, ChildState{
				ChildRef: ChildRef{ID: entry.CgroupID, Identity: entry.Identity},
				Mode:     childMode(entry), Owner: entry.Owner, Generation: entry.Generation, AccountedIncarnation: entry.AccountedIncarnation,
			})
		}
		return nil
	})
	return result, exists, err
}
