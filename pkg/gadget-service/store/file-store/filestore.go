// Copyright 2023-2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package filestore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/store"
)

const (
	GadgetBaseDir     = "/var/lib/ig"
	GadgetInstanceDir = "/var/lib/ig/gadgets"
)

type instanceManager interface {
	RunGadget(*api.GadgetInstance)
	RemoveGadget(string) error
	ReconcileGadget(context.Context, *api.GadgetInstance) error
}

type FileStore struct {
	api.GadgetInstanceManagerServer
	instanceMgr instanceManager
	mu          sync.Mutex
	directory   string
	observed    map[string]string
	watchCancel context.CancelFunc
	watchWG     sync.WaitGroup
}

func New(mgr *instancemanager.Manager) (store.Store, error) {
	fs := &FileStore{
		instanceMgr: mgr,
		directory:   GadgetInstanceDir,
		observed:    make(map[string]string),
	}
	err := fs.init()
	if err != nil {
		return nil, err
	}
	return fs, nil
}

func (s *FileStore) init() error {
	err := os.MkdirAll(GadgetBaseDir, 0o755)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("creating directory %q: %w", GadgetBaseDir, err)
	}
	err = os.MkdirAll(GadgetInstanceDir, 0o700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("creating directory %q: %w", GadgetInstanceDir, err)
	}
	return nil
}

// loadGadgetFile loads a gadget configuration from a file
func loadGadgetFile(filename string) (*api.CreateGadgetInstanceRequest, error) {
	// filename is sanitized to contain only hex characters by the instance manager
	blob, err := os.ReadFile(filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("gadget instance not found at %q", filename)
		}
		return nil, fmt.Errorf("read file %q: %w", filename, err)
	}
	gadget := &api.CreateGadgetInstanceRequest{}
	err = protojson.Unmarshal(blob, gadget)
	if err != nil {
		return nil, fmt.Errorf("unmarshal gadget info for file %q: %w", filename, err)
	}
	if gadget.GadgetInstance == nil || gadget.GadgetInstance.GadgetConfig == nil {
		return nil, fmt.Errorf("missing gadget instance or configuration in %q", filename)
	}
	return gadget, nil
}

// getGadgets returns a list of all installed gadget configurations
func (s *FileStore) getGadgets() ([]*api.CreateGadgetInstanceRequest, error) {
	files, err := os.ReadDir(s.directory)
	if err != nil {
		return nil, fmt.Errorf("reading gadgets: %w", err)
	}

	res := make([]*api.CreateGadgetInstanceRequest, 0)
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".gadget") {
			continue
		}
		gadget, err := loadGadgetFile(filepath.Join(s.directory, file.Name()))
		if err != nil {
			log.Warnf("could not read gadget file: %v", err)
			continue
		}
		res = append(res, gadget)
	}
	return res, nil
}

func (s *FileStore) CreateGadgetInstance(ctx context.Context, req *api.CreateGadgetInstanceRequest) (*api.CreateGadgetInstanceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store to gadget file
	gadgetBlob, err := protojson.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encoding gadget information: %w", err)
	}

	// req.GadgetInstance.Id is sanitized in service-store.go
	filename := filepath.Join(s.directory, fmt.Sprintf("%s.gadget", req.GadgetInstance.Id))

	// A removed file may still own a live instance until the watcher handles
	// deletion. Creating the same ID must not orphan that retained instance.
	if _, tracked := s.observed[req.GadgetInstance.Id]; tracked {
		return nil, fmt.Errorf("gadget with id %q already exists", req.GadgetInstance.Id)
	}

	// check whether a gadget with the given id or name already exists
	gadgets, err := s.getGadgets()
	if err != nil {
		return nil, fmt.Errorf("reading existing gadgets: %w", err)
	}
	for _, gadget := range gadgets {
		if gadget.GadgetInstance.Id == req.GadgetInstance.Id {
			return nil, fmt.Errorf("gadget with id %q already exists", req.GadgetInstance.Id)
		}
		if gadget.GadgetInstance.Name == req.GadgetInstance.Name {
			return nil, fmt.Errorf("gadget with name %q already exists", req.GadgetInstance.Name)
		}
	}

	// Reserve the ID independently of the file's contents. Invalid desired
	// configuration may still own a running last-good instance, and an external
	// writer can create the file after the parsed-name checks above.
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("gadget with id %q already exists", req.GadgetInstance.Id)
	}
	if err != nil {
		return nil, fmt.Errorf("creating gadget file: %w", err)
	}
	_, writeErr := file.Write(gadgetBlob)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return nil, fmt.Errorf("storing gadget information: %w", errors.Join(err, os.Remove(filename)))
	}

	log.Debugf("installing new gadget %q", req.GadgetInstance.Id)
	s.instanceMgr.RunGadget(req.GadgetInstance)
	s.observed[req.GadgetInstance.Id] = string(gadgetBlob)
	return &api.CreateGadgetInstanceResponse{
		Result:         0,
		GadgetInstance: req.GadgetInstance,
	}, nil
}

func (s *FileStore) ListGadgetInstances(ctx context.Context, request *api.ListGadgetInstancesRequest) (*api.ListGadgetInstanceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	gadgets, err := s.getGadgets()
	if err != nil {
		return nil, fmt.Errorf("loading gadgets: %w", err)
	}
	persistentGadgets := make([]*api.GadgetInstance, 0, len(gadgets))
	for _, gadget := range gadgets {
		persistentGadgets = append(persistentGadgets, gadget.GadgetInstance)
	}
	return &api.ListGadgetInstanceResponse{GadgetInstances: persistentGadgets}, nil
}

func (s *FileStore) GetGadgetInstance(ctx context.Context, req *api.GadgetInstanceId) (*api.GadgetInstance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.directory, fmt.Sprintf("%s.gadget", req.Id))
	gadget, err := loadGadgetFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading gadget: %w", err)
	}
	return gadget.GadgetInstance, nil
}

func (s *FileStore) RemoveGadgetInstance(ctx context.Context, request *api.GadgetInstanceId) (*api.StatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.directory, fmt.Sprintf("%s.gadget", request.Id))
	// Removal addresses the file's sanitized ID, never its desired contents.
	// The last-good instance may still run after an invalid administrator edit.
	_, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return &api.StatusResponse{Result: 1, Message: err.Error()}, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		if _, tracked := s.observed[request.Id]; !tracked {
			return &api.StatusResponse{Result: 1, Message: err.Error()}, nil
		}
	}

	err = s.instanceMgr.RemoveGadget(request.Id)
	if err != nil && !errors.Is(err, instancemanager.ErrNotFound) {
		return &api.StatusResponse{Result: 1, Message: err.Error()}, nil
	}
	err = os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return &api.StatusResponse{Result: 1, Message: err.Error()}, nil
	}
	delete(s.observed, request.Id)
	return &api.StatusResponse{Result: 0}, nil
}
