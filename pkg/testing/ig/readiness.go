// Copyright 2019-2024 The Inspektor Gadget authors
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

package ig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"

	igconfig "github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

// stderr is piped, so logrus uses its non-terminal text format. Require the
// complete remote message: the bare client "running..." precedes subscription.
// A target can finish while the client is still waiting for other targets.
// Both error and clean remote termination invalidate the startup barrier.
var remoteTerminated = regexp.MustCompile(`(?:^| )level=debug msg="([a-zA-Z0-9._-]+) +\| (done from server side \(.*\))"(?: |$)`)

var remoteRunning = regexp.MustCompile(`(?:^| )level=debug msg="([a-zA-Z0-9._-]+) +\| running\.\.\."(?: |$)`)

type nodeReadiness struct {
	expected    map[string]bool
	mu          sync.Mutex
	pending     string
	missing     map[string]bool
	ready       chan struct{}
	failed      chan struct{}
	terminalErr error
}

func newNodeReadiness(nodes []string) *nodeReadiness {
	r := &nodeReadiness{
		expected: make(map[string]bool),
		missing:  make(map[string]bool),
		ready:    make(chan struct{}),
		failed:   make(chan struct{}),
	}
	for _, node := range nodes {
		r.missing[node] = true
		r.expected[node] = true
	}
	return r
}

func (r *nodeReadiness) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending += string(p)
	for {
		line, rest, ok := strings.Cut(r.pending, "\n")
		if !ok {
			break
		}
		r.pending = rest
		if match := remoteTerminated.FindStringSubmatch(line); len(match) == 3 && r.expected[match[1]] && r.terminalErr == nil {
			r.terminalErr = fmt.Errorf("node %s terminated before capture: %s", match[1], match[2])
			close(r.failed)
		}
		match := remoteRunning.FindStringSubmatch(line)
		if len(match) == 2 && r.missing[match[1]] {
			delete(r.missing, match[1])
			if len(r.missing) == 0 {
				close(r.ready)
			}
		}
	}
	return len(p), nil
}

func (r *nodeReadiness) failure(cause error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	nodes := make([]string, 0, len(r.missing))
	for node := range r.missing {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	return fmt.Errorf("remote gadget readiness missing nodes [%s]: %w", strings.Join(nodes, ", "), cause)
}

func (r *nodeReadiness) wait(ctx context.Context, exited <-chan struct{}, exitError func() error) error {
	if len(r.expected) == 0 {
		return fmt.Errorf("no expected gadget nodes")
	}
	exitFailure := func() error {
		err := exitError()
		if err == nil {
			err = fmt.Errorf("command exited before capture")
		}
		return r.failure(err)
	}
	select {
	case <-ctx.Done():
		return r.failure(ctx.Err())
	case <-exited:
		return exitFailure()
	case <-r.failed:
		return r.failure(r.terminalErr)
	case <-r.ready:
		// Do not release a workload if cancellation or target/process exit is known.
		if err := ctx.Err(); err != nil {
			return r.failure(err)
		}
		select {
		case <-r.failed:
			return r.failure(r.terminalErr)
		case <-exited:
			return exitFailure()
		default:
			return nil
		}
	}
}

func (ig *runner) kubernetesTargets(ctx context.Context) ([]string, string, error) {
	flags := pflag.NewFlagSet("test readiness", pflag.ContinueOnError)
	flags.ParseErrorsAllowlist.UnknownFlags = true
	config := genericclioptions.NewConfigFlags(false)
	config.AddFlags(flags)
	var configPath string
	flags.StringVar(&configPath, "config", "", "")
	var selection string
	var namespace string
	flags.StringVar(&selection, "node", "", "")
	flags.StringVar(&namespace, "gadget-namespace", grpcruntime.DefaultGadgetNamespace, "")
	if err := flags.Parse(ig.flags); err != nil {
		return nil, "", err
	}
	if err := rejectImplicitTargetConfig(flags, configPath); err != nil {
		return nil, "", err
	}
	client, err := k8sutil.NewClientsetFromConfigFlags(config)
	if err != nil {
		return nil, "", err
	}
	if !flags.Changed("gadget-namespace") {
		namespace, err = gadgetNamespace(ctx, client)
		if err != nil {
			return nil, "", err
		}
	}
	nodes, err := gadgetNodes(ctx, client, namespace, params.SplitStringSlice(selection))
	if err != nil {
		return nil, "", err
	}
	// Replace discovery inputs with the exact frozen targets used by the barrier.
	filtered := make([]string, 0, len(ig.flags))
	for i := 0; i < len(ig.flags); i++ {
		arg := ig.flags[i]
		if arg == "--node" || arg == "--gadget-namespace" {
			i++
			continue
		}
		if strings.HasPrefix(arg, "--node=") || strings.HasPrefix(arg, "--gadget-namespace=") {
			continue
		}
		filtered = append(filtered, arg)
	}
	ig.flags = filtered
	return nodes, namespace, nil
}

func gadgetNodes(ctx context.Context, client kubernetes.Interface, namespace string, selected []string) ([]string, error) {
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: "k8s-app=gadget"})
	if err != nil {
		return nil, err
	}
	available := make(map[string]bool)
	for _, pod := range pods.Items {
		if pod.Spec.NodeName == "" && len(selected) == 0 {
			return nil, fmt.Errorf("gadget pod %s/%s has no assigned node", namespace, pod.Name)
		}
		available[pod.Spec.NodeName] = true
	}
	if len(available) == 0 {
		return nil, fmt.Errorf("no gadget pods found in namespace %q", namespace)
	}
	nodes := make([]string, 0, len(available))
	if len(selected) > 0 {
		seen := make(map[string]bool)
		for _, node := range selected {
			if !available[node] {
				return nil, fmt.Errorf("node %q does not have a gadget pod in namespace %q", node, namespace)
			}
			if seen[node] {
				return nil, fmt.Errorf("duplicate selected node %q", node)
			}
			nodes = append(nodes, node)
			seen[node] = true
		}
	} else {
		for node := range available {
			nodes = append(nodes, node)
		}
	}
	sort.Strings(nodes)
	return nodes, nil
}

// Match kubectl-gadget namespace auto-discovery, but fail closed on API errors.
func gadgetNamespace(ctx context.Context, client kubernetes.Interface) (string, error) {
	daemonSets, err := client.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{
		FieldSelector: "metadata.name=gadget", LabelSelector: "k8s-app=gadget",
	})
	if err != nil {
		return "", err
	}
	switch len(daemonSets.Items) {
	case 0:
		return grpcruntime.DefaultGadgetNamespace, nil
	case 1:
		return daemonSets.Items[0].Namespace, nil
	default:
		return "", fmt.Errorf("multiple gadget namespaces; specify --gadget-namespace")
	}
}

// The CLI applies its own config/env overrides before loading Kubernetes config.
// Keep this test helper small: require those target overrides to be explicit,
// rather than silently discovering in a different cluster or reimplementing CLI
// configuration. The standard KUBECONFIG loader is still used normally.
func rejectImplicitTargetConfig(flags *pflag.FlagSet, path string) error {
	explicit := path != ""
	if !explicit {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		path = filepath.Join(home, ".ig", "config.yaml")
	}
	config := igconfig.NewWithPath(path)
	if err := config.ReadInConfig(); explicit && err != nil {
		return err
	}
	for _, name := range []string{"kubeconfig", "context", "cluster", "user", "server", "tls-server-name", "insecure-skip-tls-verify", "certificate-authority", "client-certificate", "client-key", "token", "as", "as-group", "as-uid", "username", "password", "gadget-namespace", "node"} {
		key := name
		if name == "gadget-namespace" || name == "node" {
			key = igconfig.RuntimeKey + "." + name
		}
		if err := config.BindEnv(key); err != nil {
			return err
		}
		if config.IsSet(key) && !flags.Changed(name) {
			return fmt.Errorf("readiness discovery requires explicit --%s instead of implicit Inspektor Gadget config/environment override", name)
		}
	}
	return nil
}
