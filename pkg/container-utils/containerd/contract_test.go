// Copyright 2026 The Inspektor Gadget authors
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

package containerd

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	imagesapi "github.com/containerd/containerd/api/services/images/v1"
	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	versionapi "github.com/containerd/containerd/api/services/version/v1"
	apitypes "github.com/containerd/containerd/api/types"
	tasktypes "github.com/containerd/containerd/api/types/task"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
)

// This fixture implements only the discovery RPC subset present in containerd
// 1.7. It is not a daemon/runtime or full cross-version compatibility test.
type discoveryFixture struct {
	containersapi.UnimplementedContainersServer
	record         *containersapi.Container
	taskStatus     tasktypes.Status
	taskError      error
	containerError error
	imageError     error
	mu             sync.Mutex
	calls          map[string]int
}
type fixtureTasks struct {
	tasksapi.UnimplementedTasksServer
	f *discoveryFixture
}
type fixtureImages struct {
	imagesapi.UnimplementedImagesServer
	f *discoveryFixture
}
type fixtureVersion struct {
	versionapi.UnimplementedVersionServer
}

func (fixtureVersion) Version(context.Context, *emptypb.Empty) (*versionapi.VersionResponse, error) {
	return &versionapi.VersionResponse{Version: "1.7.36"}, nil
}

func (f *discoveryFixture) Get(_ context.Context, r *containersapi.GetContainerRequest) (*containersapi.GetContainerResponse, error) {
	if r.ID != "ctr" {
		return nil, status.Error(codes.NotFound, "unknown container")
	}
	if f.containerError != nil {
		return nil, f.containerError
	}
	return &containersapi.GetContainerResponse{Container: f.record}, nil
}

func (f *discoveryFixture) List(_ context.Context, r *containersapi.ListContainersRequest) (*containersapi.ListContainersResponse, error) {
	if len(r.Filters) != 0 {
		return nil, status.Error(codes.InvalidArgument, "unexpected filters")
	}
	if f.containerError != nil {
		return nil, f.containerError
	}
	return &containersapi.ListContainersResponse{Containers: []*containersapi.Container{f.record}}, nil
}

func (s fixtureTasks) Get(_ context.Context, r *tasksapi.GetRequest) (*tasksapi.GetResponse, error) {
	if r.ContainerID != "ctr" || r.ExecID != "" {
		return nil, status.Error(codes.InvalidArgument, "unexpected task fields")
	}
	if s.f.taskError != nil {
		return nil, s.f.taskError
	}
	return &tasksapi.GetResponse{Process: &tasktypes.Process{ContainerID: "ctr", ID: "ctr", Pid: 123, Status: s.f.taskStatus}}, nil
}

func (s fixtureImages) Get(_ context.Context, r *imagesapi.GetImageRequest) (*imagesapi.GetImageResponse, error) {
	if r.Name != "image:test" {
		return nil, status.Error(codes.InvalidArgument, "unexpected image name")
	}
	if s.f.imageError != nil {
		return nil, s.f.imageError
	}
	return &imagesapi.GetImageResponse{Image: &imagesapi.Image{Name: r.Name, Target: &apitypes.Descriptor{Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}, nil
}

func newDiscoveryFixture(t *testing.T, namespace string) (*ContainerdClient, *discoveryFixture, *grpc.ClientConn) {
	t.Helper()
	f := &discoveryFixture{record: &containersapi.Container{ID: "ctr", Image: "image:test", Labels: map[string]string{LabelK8sContainerName: "app", runtimeclient.ContainerLabelK8sPodName: "pod", runtimeclient.ContainerLabelK8sPodNamespace: "ns"}, Spec: &anypb.Any{TypeUrl: "types.containerd.io/opencontainers/runtime-spec/1/Spec", Value: []byte(`{"linux":{"cgroupsPath":"/example"},"mounts":[{"source":"/host","destination":"/container"}]}`)}}, taskStatus: tasktypes.Status_RUNNING, calls: map[string]int{}}
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		if got := md.Get("containerd-namespace"); len(got) != 1 || got[0] != namespace {
			return nil, status.Error(codes.InvalidArgument, "incorrect namespace")
		}
		f.mu.Lock()
		f.calls[info.FullMethod]++
		f.mu.Unlock()
		return handler(ctx, req)
	}))
	containersapi.RegisterContainersServer(server, f)
	tasksapi.RegisterTasksServer(server, fixtureTasks{f: f})
	imagesapi.RegisterImagesServer(server, fixtureImages{f: f})
	versionapi.RegisterVersionServer(server, fixtureVersion{})
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	require.NoError(t, err)
	sdk, err := containerd.NewWithConn(conn)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(namespaces.WithNamespace(context.Background(), namespace), 5*time.Second)
	c := &ContainerdClient{client: sdk, ctx: ctx}
	t.Cleanup(func() { cancel(); _ = c.Close(); server.Stop(); _ = listener.Close() })
	version, err := sdk.Version(ctx)
	require.NoError(t, err)
	require.Equal(t, "1.7.36", version.Version)
	return c, f, conn
}

func TestDiscoveryContractCreationWithoutTask(t *testing.T) {
	for _, ns := range []string{runtimeclient.K8sContainerdNamespace, "custom"} {
		t.Run(ns, func(t *testing.T) {
			c, f, conn := newDiscoveryFixture(t, ns)
			data, err := c.GetContainer("ctr")
			require.NoError(t, err)
			require.Equal(t, "ctr", data.Runtime.ContainerID)
			require.Equal(t, "app", data.Runtime.ContainerName)
			require.Equal(t, runtimeclient.StateRunning, data.Runtime.State)
			require.Equal(t, "image:test", data.Runtime.ContainerImageName)
			require.Equal(t, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", data.Runtime.ContainerImageDigest)
			require.Equal(t, "pod", data.K8s.PodName)
			require.Equal(t, "ns", data.K8s.Namespace)
			f.mu.Lock()
			require.Zero(t, f.calls["/containerd.services.tasks.v1.Tasks/Get"])
			f.mu.Unlock()
			require.NoError(t, c.Close())
			require.Equal(t, connectivity.Shutdown, conn.GetState())
		})
	}
}

func TestDiscoveryContractStatuses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  tasktypes.Status
		want    string
		missing bool
	}{{"created", tasktypes.Status_CREATED, runtimeclient.StateCreated, false}, {"running", tasktypes.Status_RUNNING, runtimeclient.StateRunning, false}, {"stopped", tasktypes.Status_STOPPED, runtimeclient.StateExited, false}, {"paused", tasktypes.Status_PAUSED, runtimeclient.StateUnknown, false}, {"missing", 0, runtimeclient.StateCreated, true}} {
		t.Run(tc.name, func(t *testing.T) {
			c, f, _ := newDiscoveryFixture(t, "k8s.io")
			f.taskStatus = tc.status
			if tc.missing {
				f.taskError = status.Error(codes.NotFound, "no task")
			}
			data, err := c.GetContainers()
			require.NoError(t, err)
			require.Len(t, data, 1)
			require.Equal(t, tc.want, data[0].Runtime.State)
		})
	}
}

func TestDiscoveryContractDetails(t *testing.T) {
	c, f, _ := newDiscoveryFixture(t, "k8s.io")
	data, err := c.GetContainerDetails("containerd://ctr")
	require.NoError(t, err)
	require.Equal(t, 123, data.Pid)
	require.Equal(t, "/example", data.CgroupsPath)
	require.Equal(t, []runtimeclient.ContainerMountData{{Source: "/host", Destination: "/container"}}, data.Mounts)
	f.record.Spec = nil
	_, err = c.GetContainerDetails("ctr")
	require.ErrorContains(t, err, "getting spec")
	f.record.Spec = &anypb.Any{Value: []byte("bad json")}
	_, err = c.GetContainerDetails("ctr")
	require.ErrorContains(t, err, "getting spec")
	f.taskError = status.Error(codes.NotFound, "no task")
	_, err = c.GetContainerDetails("ctr")
	require.ErrorContains(t, err, "zero pid")
}

func TestDiscoveryContractErrorsAndSandbox(t *testing.T) {
	c, f, _ := newDiscoveryFixture(t, "k8s.io")
	for _, code := range []codes.Code{codes.NotFound, codes.Unimplemented, codes.DeadlineExceeded} {
		f.containerError = status.Error(code, "fixture failure")
		_, err := c.GetContainer("ctr")
		require.ErrorContains(t, err, "loading container")
		_, err = c.GetContainers()
		require.ErrorContains(t, err, "listing containers")
	}
	f.containerError = nil
	f.imageError = status.Error(codes.NotFound, "no image")
	_, err := c.GetContainer("ctr")
	require.ErrorContains(t, err, "getting image")
	f.imageError = nil
	f.taskError = status.Error(codes.Unimplemented, "no task service")
	data, err := c.GetContainers()
	require.NoError(t, err)
	require.Empty(t, data)
	f.record.Labels[LabelK8sContainerdKind] = LabelK8sContainerdKindSandbox
	_, err = c.GetContainer("ctr")
	require.ErrorIs(t, err, runtimeclient.ErrPauseContainer)
	data, err = c.GetContainers()
	require.NoError(t, err)
	require.Empty(t, data)
}

func TestDiscoveryConstructorIsLazy(t *testing.T) {
	for _, tc := range []struct {
		config *containerutilsTypes.ExtraConfig
		want   string
	}{{nil, "k8s.io"}, {&containerutilsTypes.ExtraConfig{}, "k8s.io"}, {&containerutilsTypes.ExtraConfig{Namespace: "custom"}, "custom"}} {
		client, err := NewContainerdClient(t.TempDir()+"/absent.sock", "", tc.config)
		require.NoError(t, err)
		namespace, ok := namespaces.Namespace(client.(*ContainerdClient).ctx)
		require.True(t, ok)
		require.Equal(t, tc.want, namespace)
		require.NoError(t, client.Close())
	}
}
