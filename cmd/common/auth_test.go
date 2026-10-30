// Copyright 2023 The Inspektor Gadget authors
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

package common

import (
	"reflect"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

// Only construct commands and parse flags: never execute auth or credential helpers.
func TestAuthCommandContracts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		newCommand func() *cobra.Command
		defaults   map[string]string
		shorthands map[string]string
		args       []string
		changed    map[string]string
	}{
		{name: "login", newCommand: NewLoginCmd,
			defaults:   map[string]string{"authfile": oci.DefaultAuthFile, "compat-auth-file": "", "cert-dir": "", "password": "", "username": "", "password-stdin": "false", "get-login": "false", "verbose": "false"},
			shorthands: map[string]string{"password": "p", "username": "u", "verbose": "v"},
			args:       []string{"--authfile", "custom-auth.json", "--compat-auth-file", "docker-auth.json", "--cert-dir", "certificates", "-u", "user", "-p", "example", "--password-stdin", "--get-login", "-v", "registry.example.invalid"},
			changed:    map[string]string{"authfile": "custom-auth.json", "compat-auth-file": "docker-auth.json", "cert-dir": "certificates", "username": "user", "password": "example", "password-stdin": "true", "get-login": "true", "verbose": "true"},
		},
		{name: "logout", newCommand: NewLogoutCmd,
			defaults:   map[string]string{"authfile": oci.DefaultAuthFile, "compat-auth-file": "", "all": "false"},
			shorthands: map[string]string{"all": "a"},
			args:       []string{"--authfile", "custom-auth.json", "--compat-auth-file", "docker-auth.json", "-a", "registry.example.invalid"},
			changed:    map[string]string{"authfile": "custom-auth.json", "compat-auth-file": "docker-auth.json", "all": "true"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := tc.newCommand()
			if cmd.Use != tc.name+" [command options] REGISTRY" || !cmd.SilenceUsage || cmd.RunE == nil || cmd.Args != nil {
				t.Fatalf("command contract changed: %+v", cmd)
			}
			got := map[string]string{}
			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				got[flag.Name] = flag.Value.String()
				if flag.Shorthand != tc.shorthands[flag.Name] {
					t.Errorf("%s shorthand = %q", flag.Name, flag.Shorthand)
				}
			})
			if !reflect.DeepEqual(got, tc.defaults) {
				t.Fatalf("defaults = %v; want %v", got, tc.defaults)
			}
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cmd.Flags().Args(), []string{"registry.example.invalid"}) {
				t.Fatalf("registry args = %v", cmd.Flags().Args())
			}
			for name, want := range tc.changed {
				if got := cmd.Flags().Lookup(name).Value.String(); got != want {
					t.Errorf("%s = %q; want %q", name, got, want)
				}
			}
			// Independent command constructions must not share option state.
			fresh := tc.newCommand()
			for name, want := range tc.defaults {
				if got := fresh.Flags().Lookup(name).Value.String(); got != want {
					t.Errorf("fresh %s = %q; want %q", name, got, want)
				}
			}
		})
	}
}
