// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	execpolicy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/processlaunch"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

func newLaunchCommand(runtime *local.Runtime) *cobra.Command {
	var policyFile string
	var startupTimeout time.Duration
	runtimeParams := runtime.ParamDescs().ToParams()
	runtimeGlobals := runtime.GlobalParamDescs().ToParams()
	ociParams := apihelpers.ToParamDescs(ocihandler.OciHandler.InstanceParams()).ToParams()
	opGlobals := map[string]*params.Params{}
	ops := make([]operators.DataOperator, 0)
	for _, op := range operators.GetDataOperators() {
		// Controlled launches bind one host process directly. Container discovery
		// and its runtime connections are unnecessary for this command.
		if op.Name() == localmanager.OperatorName {
			continue
		}
		ops = append(ops, op)
	}
	for _, op := range ops {
		opGlobals[op.Name()] = apihelpers.ToParamDescs(op.GlobalParams()).ToParams()
	}
	cmd := &cobra.Command{
		Use:          "launch IMAGE --policy FILE -- COMMAND [ARGS...]",
		Short:        "Start a process after its execution policy is attached",
		SilenceUsage: true,
		Args: func(cmd *cobra.Command, args []string) error {
			if cmd.ArgsLenAtDash() != 1 || len(args) < 2 {
				return fmt.Errorf("specify one gadget image followed by -- COMMAND [ARGS...]")
			}
			if policyFile == "" {
				return fmt.Errorf("--policy is required")
			}
			if startupTimeout <= 0 {
				return fmt.Errorf("--startup-timeout must be positive")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			input, err := readLaunchPolicy(policyFile)
			if err != nil {
				return err
			}
			// Validate before creating even the waiting bootstrap. The actual identity
			// replaces these placeholders below, before anything reaches the gadget.
			if _, err := execpolicy.ParseLaunch(bytes.NewReader(input), execpolicy.DefaultLimits(), execpolicy.Process{
				Node: "pending", BootID: "pending", HostPID: 1, StartTimeTicks: 1,
			}); err != nil {
				return err
			}
			for _, op := range ops {
				if err := common.SetFlagsForParams(cmd, opGlobals[op.Name()], config.OperatorKey+"."+op.Name()); err != nil {
					return err
				}
			}
			if err := common.SetFlagsForParams(cmd, ociParams, config.OperatorKey+"."+ocihandler.OciHandler.Name()); err != nil {
				return err
			}
			if err := runtime.Init(runtimeGlobals); err != nil {
				return err
			}
			defer runtime.Close()
			for _, op := range ops {
				if err := op.Init(opGlobals[op.Name()]); err != nil {
					return fmt.Errorf("initializing operator %s: %w", op.Name(), err)
				}
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			child, err := processlaunch.Start(ctx, args[1:], processlaunch.Options{Stdin: cmd.InOrStdin(), Stdout: cmd.OutOrStdout(), Stderr: cmd.ErrOrStderr(), Env: os.Environ()})
			if err != nil {
				return err
			}
			defer child.Close()
			identity := child.Identity()
			document, err := execpolicy.ParseLaunch(bytes.NewReader(input), execpolicy.DefaultLimits(), execpolicy.Process{
				Node: identity.Node, BootID: identity.BootID, HostPID: int(identity.PID), StartTimeTicks: identity.StartTimeTicks,
			})
			if err != nil {
				return err
			}
			encoded, err := yaml.Marshal(document)
			if err != nil {
				return err
			}
			values := launchParamValues(string(encoded), ociParams)
			// Keep enforcement attached until the selected process has been reaped.
			runCtx, cancel := context.WithCancel(child.Context(context.WithoutCancel(ctx)))
			defer cancel()
			started := make(chan struct{})
			var startupMu sync.Mutex
			released := false
			deadline := time.Now().Add(startupTimeout)
			gadgetCtx := gadgetcontext.New(runCtx, args[0], gadgetcontext.WithDataOperators(ops...), gadgetcontext.WithOnStarted(func() error {
				startupMu.Lock()
				defer startupMu.Unlock()
				if !time.Now().Before(deadline) {
					return fmt.Errorf("gadget startup exceeded %s", startupTimeout)
				}
				if err := child.Release(); err != nil {
					return err
				}
				released = true
				close(started)
				return nil
			}))
			gadgetDone := make(chan error, 1)
			childDone := make(chan error, 1)
			go func() { gadgetDone <- runtime.RunGadget(gadgetCtx, runtimeParams, values) }()
			go func() { childDone <- child.Wait() }()
			timer := time.NewTimer(time.Until(deadline))
			defer timer.Stop()
			timeout := timer.C
			for {
				select {
				case <-started:
					timer.Stop()
					timeout = nil
					started = nil
				case err := <-childDone:
					cancel()
					runtimeErr := <-gadgetDone
					if err != nil {
						return fmt.Errorf("application exited: %w", err)
					}
					return runtimeErr
				case err := <-gadgetDone:
					child.Close()
					cancel()
					<-childDone
					if err != nil {
						return err
					}
					return fmt.Errorf("gadget stopped before the application exited")
				case <-timeout:
					startupMu.Lock()
					alreadyReleased := released
					startupMu.Unlock()
					if alreadyReleased {
						timeout = nil
						continue
					}
					child.Close()
					cancel()
					<-childDone
					<-gadgetDone
					return fmt.Errorf("gadget startup exceeded %s", startupTimeout)
				case <-ctx.Done():
					child.Close()
					cancel()
					<-childDone
					<-gadgetDone
					return ctx.Err()
				}
			}
		},
	}
	cmd.Flags().StringVar(&policyFile, "policy", "", "Execution policy YAML without a binding (the launcher supplies it)")
	cmd.Flags().DurationVar(&startupTimeout, "startup-timeout", 30*time.Second, "Maximum time to attach the policy before starting the application")
	common.AddOCIFlags(cmd, ociParams, nil, runtime)
	for _, op := range ops {
		common.AddOCIFlags(cmd, opGlobals[op.Name()], nil, runtime)
	}
	return cmd
}

func readLaunchPolicy(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open policy: %w", err)
	}
	defer f.Close()
	limit := execpolicy.DefaultLimits().MaxBytes
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("policy exceeds %d bytes", limit)
	}
	return data, nil
}

// Keep the OCI instance settings alongside the nested WASM parameter.
func launchParamValues(policy string, ociParams *params.Params) api.ParamValues {
	values := api.ParamValues{"operator.oci.wasm.exec-policy": policy}
	ociParams.CopyToMap(values, "operator.oci.")
	return values
}
