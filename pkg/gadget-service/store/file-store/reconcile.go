// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package filestore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
)

// ResumeStoredGadgets also watches administrator edits to persisted .gadget
// files. Atomic file replacement is recommended; malformed partial writes retain
// the active instance. Removing a file explicitly removes its instance.
func (s *FileStore) ResumeStoredGadgets() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.watchCancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.reconcileFiles(ctx); err != nil {
		cancel()
		return err
	}
	s.watchCancel = cancel
	s.watchWG.Add(1)
	go func() {
		defer s.watchWG.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.mu.Lock()
				if err := s.reconcileFiles(ctx); err != nil {
					log.Warnf("reconciling gadget files: %v", err)
				}
				s.mu.Unlock()
			}
		}
	}()
	return nil
}

func (s *FileStore) Close() {
	s.mu.Lock()
	cancel := s.watchCancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
		s.watchWG.Wait()
	}
}

// Caller holds mu, serializing file reconciliation with create/delete RPCs.
func (s *FileStore) reconcileFiles(ctx context.Context) error {
	files, err := os.ReadDir(s.directory)
	if err != nil {
		return fmt.Errorf("reading gadget directory: %w", err)
	}
	present := make(map[string]bool)
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".gadget") {
			continue
		}
		id := strings.TrimSuffix(file.Name(), ".gadget")
		present[id] = true
		raw, err := os.ReadFile(filepath.Join(s.directory, file.Name()))
		if err != nil {
			log.Warnf("reading gadget file %q: %v", file.Name(), err)
			continue
		}
		if previous, ok := s.observed[id]; ok && previous == string(raw) {
			continue
		}
		// A changed file invalidates the successful-content cache even when it
		// cannot be parsed. Restoring it must obtain a fresh acknowledgement.
		// Retain existing ownership so deletion still removes the instance.
		if _, tracked := s.observed[id]; tracked {
			s.observed[id] = ""
		}
		request := &api.CreateGadgetInstanceRequest{}
		if err := protojson.Unmarshal(raw, request); err != nil {
			log.Warnf("parsing gadget file %q: %v", file.Name(), err)
			continue
		}
		if request.GadgetInstance == nil || request.GadgetInstance.GadgetConfig == nil || request.GadgetInstance.Id != id {
			log.Warnf("gadget file %q must contain a configuration with matching instance ID", file.Name())
			continue
		}
		updateCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = s.instanceMgr.ReconcileGadget(updateCtx, request.GadgetInstance)
		cancel()
		if err != nil {
			// Reconcile a restored last-good file too, so the manager can clear
			// the rejected update diagnostic. Keep the key for deletion tracking.
			s.observed[id] = ""
			log.Warnf("updating gadget file %q: %v", file.Name(), err)
			continue
		}
		s.observed[id] = string(raw)
	}
	for id := range s.observed {
		if present[id] {
			continue
		}
		if err := s.instanceMgr.RemoveGadget(id); err != nil && !errors.Is(err, instancemanager.ErrNotFound) {
			log.Warnf("removing gadget instance %q: %v", id, err)
			continue
		}
		delete(s.observed, id)
	}
	return nil
}
