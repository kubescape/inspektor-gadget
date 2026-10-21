// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package wasm

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func TestParameterUpdateAcknowledgment(t *testing.T) {
	for _, mode := range []string{"success", "rejected", "missing-ack", "wrong-request", "wrong-generation", "ambiguous-state", "subscriber-error"} {
		t.Run(mode, func(t *testing.T) {
			gc := gadgetcontext.New(context.Background(), "test")
			input, err := gc.RegisterDataSource(datasource.TypeSingle, "updates")
			require.NoError(t, err)
			status, err := gc.RegisterDataSource(datasource.TypeSingle, "status")
			require.NoError(t, err)
			for name, kind := range map[string]api.Kind{"policy": api.Kind_String, "expected_generation": api.Kind_Uint64, "request_id": api.Kind_Uint64} {
				_, err = input.AddField(name, kind)
				require.NoError(t, err)
			}
			for name, kind := range map[string]api.Kind{"state": api.Kind_String, "message": api.Kind_String, "generation": api.Kind_Uint64, "request_id": api.Kind_Uint64} {
				_, err = status.AddField(name, kind)
				require.NoError(t, err)
			}
			i := &wasmOperatorInstance{gadgetCtx: gc, paramValues: map[string]string{"exec-policy": "old"}, parameterUpdates: &parameterUpdates{parameter: "exec-policy", inputName: "updates", statusName: "status", fieldName: "policy"}}
			require.NoError(t, i.initParameterUpdates())
			emit := func(gen, id uint64, state string) {
				p, err := status.NewPacketSingle()
				require.NoError(t, err)
				require.NoError(t, status.GetField("generation").PutUint64(p, gen))
				require.NoError(t, status.GetField("request_id").PutUint64(p, id))
				require.NoError(t, status.GetField("state").PutString(p, state))
				require.NoError(t, status.GetField("message").PutString(p, "diagnostic"))
				require.NoError(t, status.EmitAndRelease(p))
			}
			emit(1, 0, "enforcing")
			require.NoError(t, input.Subscribe(func(_ datasource.DataSource, d datasource.Data) error {
				gen, err := input.GetField("expected_generation").Uint64(d)
				if err != nil {
					return err
				}
				require.Equal(t, uint64(1), gen)
				id, err := input.GetField("request_id").Uint64(d)
				if err != nil {
					return err
				}
				switch mode {
				case "subscriber-error":
					emit(2, id, "enforcing")
					return fmt.Errorf("later subscriber failed")
				case "ambiguous-state":
					emit(2, id, "target-removed")
				case "success":
					emit(2, id, "enforcing")
				case "rejected":
					emit(1, id, "update-rejected")
				case "wrong-request":
					emit(2, id+1, "enforcing")
				case "wrong-generation":
					emit(3, id, "enforcing")
				}
				return nil
			}, 0))
			err = i.UpdateParameters(context.Background(), api.ParamValues{"exec-policy": "new"})
			if mode == "success" || mode == "subscriber-error" {
				require.NoError(t, err)
				require.Equal(t, "new", i.paramValues["exec-policy"])
			} else {
				require.Error(t, err)
				require.Equal(t, "old", i.paramValues["exec-policy"])
			}
		})
	}
}

func TestReadUpdateProtocol(t *testing.T) {
	for _, raw := range []string{"annotations: {}", "annotations:\n  live-update-parameter: exec-policy"} {
		v := viper.New()
		v.SetConfigType("yaml")
		require.NoError(t, v.ReadConfig(strings.NewReader(raw)))
		p, err := readUpdateProtocol(v)
		if strings.Contains(raw, "exec-policy") {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.Nil(t, p)
		}
	}
}
