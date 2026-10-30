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

package testutils

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"
)

func TestDockerHTTPHelperLifecycle(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1.44")
		calls = append(calls, r.Method+" "+path)
		w.Header().Set("Content-Type", "application/json")
		switch path {
		case "/images/create":
			_, _ = w.Write([]byte(`{"status":"done"}`))
		case "/containers/create":
			var body struct {
				Image      string
				Entrypoint []string
				HostConfig struct {
					PortBindings nat.PortMap
					Mounts       []struct{ Source, Target string }
					Privileged   bool
					Sysctls      map[string]string
					SecurityOpt  []string
				}
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			require.Equal(t, "builder:tag", body.Image)
			require.Equal(t, []string{"/bin/sh", "-c", "echo test"}, body.Entrypoint)
			require.Equal(t, "/source", body.HostConfig.Mounts[0].Source)
			require.Equal(t, "/target", body.HostConfig.Mounts[0].Target)
			require.Equal(t, nat.PortMap{"80/tcp": {{HostIP: "", HostPort: "8080"}, {HostIP: "::1", HostPort: "8081"}}, "53/udp": nil, "443/tcp": {}}, body.HostConfig.PortBindings)
			_, _ = w.Write([]byte(`{"Id":"test-id"}`))
		case "/containers/test-id/start":
			w.WriteHeader(http.StatusNoContent)
		case "/containers/test-id/wait":
			require.Equal(t, "not-running", r.URL.Query().Get("condition"))
			_, _ = w.Write([]byte(`{"StatusCode":0}`))
		case "/containers/test-id/json":
			_, _ = w.Write([]byte(`{"State":{"Pid":123},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.2"}},"Ports":{"80/tcp":[{"HostIp":"","HostPort":"8080"},{"HostIp":"::1","HostPort":"8081"}],"53/udp":null,"443/tcp":[]}}}`))
		case "/containers/test-name":
			require.Equal(t, http.MethodDelete, r.Method)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("DOCKER_HOST", srv.URL)
	t.Setenv("DOCKER_API_VERSION", "1.44")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	d := NewDockerContainer("test-name", "echo test", WithImage("builder:tag"), WithoutLogs(), WithBindMounts([]string{"/source:/target"})).(*DockerContainer)
	d.options.portBindings = nat.PortMap{"80/tcp": {{HostIP: "", HostPort: "8080"}, {HostIP: "::1", HostPort: "8081"}}, "53/udp": nil, "443/tcp": {}}
	d.Run(t)
	require.Equal(t, 123, d.pid)
	require.Equal(t, "172.17.0.2", d.ip)
	require.Equal(t, d.options.portBindings, d.portBindings)
	require.Equal(t, []string{"DELETE /containers/test-name", "POST /images/create", "POST /containers/create", "POST /containers/test-id/start", "POST /containers/test-id/wait", "GET /containers/test-id/json", "DELETE /containers/test-name"}, calls)
}

func TestDockerHTTPHelperStop(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1.44")
		calls = append(calls, r.Method+" "+path)
		w.Header().Set("Content-Type", "application/json")
		switch path {
		case "/containers/test-id/kill":
			require.Equal(t, "SIGINT", r.URL.Query().Get("signal"))
			w.WriteHeader(http.StatusNoContent)
		case "/containers/test-id/wait":
			require.Equal(t, "not-running", r.URL.Query().Get("condition"))
			_, _ = w.Write([]byte(`{"StatusCode":17}`))
		case "/containers/test-id/json":
			_, _ = w.Write([]byte(`{"State":{"ExitCode":17}}`))
		case "/containers/test-name":
			require.Equal(t, http.MethodDelete, r.Method)
			require.Equal(t, "1", r.URL.Query().Get("force"))
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("DOCKER_HOST", srv.URL)
	t.Setenv("DOCKER_API_VERSION", "1.44")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	d := NewDockerContainer("test-name", "", WithExpectedExitCode(17)).(*DockerContainer)
	require.NoError(t, d.initClient())
	d.id = "test-id"
	d.started = true
	d.Stop(t)
	require.False(t, d.started)
	require.Equal(t, []string{"POST /containers/test-id/kill", "POST /containers/test-id/wait", "GET /containers/test-id/json", "DELETE /containers/test-name"}, calls)
}
