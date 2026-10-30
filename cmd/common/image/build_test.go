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

package image

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/moby/moby/client"
	"github.com/stretchr/testify/require"
)

func TestBuilderHTTPImageContracts(t *testing.T) {
	for _, ref := range []string{"builder:tag", "builder@sha256:digest", "missing:tag"} {
		t.Run(ref, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/v1.44/images/json", r.URL.Path)
				var filters map[string]map[string]bool
				require.NoError(t, json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters))
				require.True(t, filters["reference"][ref])
				w.Header().Set("Content-Type", "application/json")
				_, err := w.Write([]byte(`[{"RepoTags":["builder:tag"],"RepoDigests":["builder@sha256:digest"]}]`))
				require.NoError(t, err)
			}))
			defer srv.Close()
			cli, err := client.New(client.WithHost(srv.URL), client.WithAPIVersion("1.44"))
			require.NoError(t, err)
			defer cli.Close()
			got, err := isImageLocallyAvailable(context.Background(), cli, ref)
			require.NoError(t, err)
			require.Equal(t, ref != "missing:tag", got)
		})
	}
}

func TestBuilderHTTPContainerLifecycle(t *testing.T) {
	for _, exit := range []int{0, 7} {
		t.Run(fmt.Sprint(exit), func(t *testing.T) {
			var calls []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/v1.44")
				calls = append(calls, r.Method+" "+path)
				w.Header().Set("Content-Type", "application/json")
				switch path {
				case "/images/json":
					_, _ = w.Write([]byte(`[{"RepoTags":["builder:tag"]}]`))
				case "/containers/create":
					var body struct {
						Image, WorkingDir, User string
						Cmd                     []string
						HostConfig              struct {
							Mounts []struct {
								Type, Source, Target string
								ReadOnly             bool
							}
						}
					}
					require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
					require.Equal(t, "builder:tag", body.Image)
					require.Equal(t, "/work", body.WorkingDir)
					require.NotEmpty(t, body.User)
					require.NotEmpty(t, body.Cmd)
					require.Len(t, body.HostConfig.Mounts, 3)
					require.Equal(t, "/work", body.HostConfig.Mounts[0].Target)
					require.False(t, body.HostConfig.Mounts[0].ReadOnly)
					require.Equal(t, "/out", body.HostConfig.Mounts[1].Target)
					require.Equal(t, "/btfhub-archive", body.HostConfig.Mounts[2].Target)
					_, _ = w.Write([]byte(`{"Id":"builder-id"}`))
				case "/containers/builder-id/start":
					w.WriteHeader(http.StatusNoContent)
				case "/containers/builder-id/wait":
					require.Equal(t, "not-running", r.URL.Query().Get("condition"))
					_, _ = fmt.Fprintf(w, `{"StatusCode":%d}`, exit)
				case "/containers/builder-id/logs":
					require.Equal(t, "1", r.URL.Query().Get("stderr"))
					if exit != 0 {
						require.Equal(t, "1", r.URL.Query().Get("stdout"))
					}
					payload := []byte("fake builder stderr\n")
					header := make([]byte, 8)
					header[0] = 2
					binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
					_, _ = w.Write(append(header, payload...))
				case "/containers/builder-id":
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
			t.Setenv("IG_SOURCE_PATH", "")
			err := buildInContainer(&cmdOpts{builderImage: "builder:tag", builderImagePull: "never", outputDir: t.TempDir(), btfgen: true, btfhubarchive: t.TempDir()}, &buildFile{EBPFSource: "program.bpf.c"})
			if exit == 0 {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "exited with status 7")
			}
			require.Equal(t, []string{"GET /images/json", "POST /containers/create", "POST /containers/builder-id/start", "POST /containers/builder-id/wait", "GET /containers/builder-id/logs", "DELETE /containers/builder-id"}, calls)
		})
	}
}

func TestBuilderHTTPPull(t *testing.T) {
	for _, pullError := range []bool{false, true} {
		t.Run(fmt.Sprint(pullError), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/v1.44/images/create", r.URL.Path)
				require.Equal(t, "docker.io/library/builder", r.URL.Query().Get("fromImage"))
				require.Equal(t, "tag", r.URL.Query().Get("tag"))
				w.Header().Set("Content-Type", "application/json")
				if pullError {
					_, _ = w.Write([]byte(`{"errorDetail":{"message":"pull denied"},"error":"pull denied"}`))
				} else {
					_, _ = w.Write([]byte(`{"status":"pulled"}`))
				}
			}))
			defer srv.Close()
			cli, err := client.New(client.WithHost(srv.URL), client.WithAPIVersion("1.44"))
			require.NoError(t, err)
			defer cli.Close()
			err = pullImage(context.Background(), cli, "builder:tag")
			if pullError {
				require.ErrorContains(t, err, "pull denied")
			} else {
				require.NoError(t, err)
			}
		})
	}
}
