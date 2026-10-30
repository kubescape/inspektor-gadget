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

package docker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/moby/moby/client"
	"github.com/stretchr/testify/require"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
)

// The fake Engine is HTTP-only: these contracts never contact a Docker daemon.
func fakeDockerClient(t *testing.T, handler http.HandlerFunc) *DockerClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	cli, err := client.New(client.WithHost(srv.URL), client.WithAPIVersion("1.44"), client.WithTimeout(DefaultTimeout))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, cli.Close()) })
	return &DockerClient{client: cli}
}

func TestDockerHTTPListContracts(t *testing.T) {
	for _, pauseOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "pause only"}[pauseOnly], func(t *testing.T) {
			c := fakeDockerClient(t, func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/v1.44/containers/json", r.URL.Path)
				require.Equal(t, "1", r.URL.Query().Get("all"))
				var filters map[string]map[string]bool
				require.NoError(t, json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters))
				require.True(t, filters["id"]["wanted"])
				w.Header().Set("Content-Type", "application/json")
				data := `[{"Id":"pause","Labels":{"io.kubernetes.docker.type":"podsandbox"}}`
				if !pauseOnly {
					data += `,{"Id":"wanted","Names":["/app"],"Image":"busybox:latest","State":"running"}`
				}
				_, err := w.Write([]byte(data + `]`))
				require.NoError(t, err)
			})
			got, err := c.GetContainer("wanted")
			if pauseOnly {
				require.True(t, errors.Is(err, runtimeclient.ErrPauseContainer))
				return
			}
			require.NoError(t, err)
			require.Equal(t, "wanted", got.Runtime.ContainerID)
			require.Equal(t, "app", got.Runtime.ContainerName)
		})
	}
}

func TestDockerHTTPInspectContracts(t *testing.T) {
	c := fakeDockerClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body string
		switch r.URL.Path {
		case "/v1.44/containers/wanted/json":
			body = `{"Id":"wanted","Name":"/app","Image":"sha256:image","State":{"Pid":123,"Status":"running"},"Config":{"Image":"busybox:latest","Labels":{}},"HostConfig":{"Cgroup":"/test-cgroup"},"Mounts":[{"Source":"/host","Destination":"/inside"}]}`
		case "/v1.44/images/sha256:image/json":
			body = `{"RepoDigests":["busybox@sha256:first","busybox@sha256:second"]}`
		default:
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
			return
		}
		_, err := w.Write([]byte(body))
		require.NoError(t, err)
	})
	got, err := c.GetContainerDetails("wanted")
	require.NoError(t, err)
	require.Equal(t, 123, got.Pid)
	require.Equal(t, "/test-cgroup", got.CgroupsPath)
	require.Equal(t, "sha256:first", got.Runtime.ContainerImageDigest)
	require.Equal(t, "/host", got.Mounts[0].Source)
	require.Equal(t, "/inside", got.Mounts[0].Destination)
}

func TestDockerHTTPInspectMissingFields(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"Id":"wanted"}`, "container state is nil"},
		{`{"State":{"Pid":0}}`, "got zero pid"},
		{`{"State":{"Pid":123}}`, "container config is nil"},
		{`{"State":{"Pid":123},"Config":{}}`, "container host config is nil"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			c := fakeDockerClient(t, func(w http.ResponseWriter, r *http.Request) {
				require.True(t, strings.HasSuffix(r.URL.Path, "/containers/wanted/json"))
				w.Header().Set("Content-Type", "application/json")
				_, err := w.Write([]byte(tc.body))
				require.NoError(t, err)
			})
			_, err := c.GetContainerDetails("wanted")
			require.EqualError(t, err, tc.want)
		})
	}
}

func TestDockerHTTPNegotiation(t *testing.T) {
	for _, version := range []string{"1.44", "1.39"} {
		t.Run(version, func(t *testing.T) {
			listed := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/_ping" {
					w.Header().Set("API-Version", version)
					return
				}
				listed = true
				if version == "1.39" {
					http.Error(w, `{"message":"client API version is too new"}`, http.StatusBadRequest)
					return
				}
				require.Equal(t, "/v"+version+"/containers/json", r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				_, err := w.Write([]byte(`[]`))
				require.NoError(t, err)
			}))
			defer srv.Close()
			// Negotiation is enabled by default. Below the SDK API 1.40 floor,
			// getAPIPath does not propagate negotiation errors; the Engine rejects
			// the resulting request. Explicit Ping reports the negotiation error.
			cli, err := client.New(client.WithHost(srv.URL), client.WithTimeout(DefaultTimeout))
			require.NoError(t, err)
			defer cli.Close()
			c := &DockerClient{client: cli}
			_, err = c.GetContainers()
			if version == "1.39" {
				require.ErrorContains(t, err, "client API version is too new")
				require.True(t, listed)
				_, err = cli.Ping(context.Background(), client.PingOptions{NegotiateAPIVersion: true})
				require.ErrorContains(t, err, "minimum supported API version is 1.40")
			} else {
				require.NoError(t, err)
				require.True(t, listed)
			}
		})
	}
}
