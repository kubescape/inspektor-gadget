// Copyright 2025 The Inspektor Gadget authors
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

package otellogs

import (
	"context"
	"net"
	"testing"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

type mockExporter struct {
	records []sdklog.Record
}

func (m *mockExporter) Export(ctx context.Context, records []sdklog.Record) error {
	// sdklog.Record is a struct, copy by value
	m.records = append(m.records, records...)
	return nil
}

func (m *mockExporter) Shutdown(ctx context.Context) error   { return nil }
func (m *mockExporter) ForceFlush(ctx context.Context) error { return nil }

type mockGadgetContext struct {
	ctx         context.Context
	dataSources map[string]datasource.DataSource
}

func (m *mockGadgetContext) ID() string               { return "test-id" }
func (m *mockGadgetContext) Name() string             { return "test-gadget" }
func (m *mockGadgetContext) Context() context.Context { return m.ctx }
func (m *mockGadgetContext) Logger() logger.Logger    { return logger.DefaultLogger() }
func (m *mockGadgetContext) ExtraInfo() bool          { return false }
func (m *mockGadgetContext) Cancel()                  {}
func (m *mockGadgetContext) SerializeGadgetInfo(requestExtraInfo bool) (*api.GadgetInfo, error) {
	return nil, nil
}
func (m *mockGadgetContext) ImageName() string { return "test-image" }
func (m *mockGadgetContext) RegisterDataSource(t datasource.Type, name string) (datasource.DataSource, error) {
	return nil, nil
}

func (m *mockGadgetContext) GetDataSources() map[string]datasource.DataSource { return m.dataSources }
func (m *mockGadgetContext) SetVar(name string, value any)                    {}
func (m *mockGadgetContext) GetVar(name string) (any, bool)                   { return nil, false }
func (m *mockGadgetContext) Params() []*api.Param                             { return nil }
func (m *mockGadgetContext) SetParams(params []*api.Param)                    {}
func (m *mockGadgetContext) SetMetadata(metadata []byte) error                { return nil }
func (m *mockGadgetContext) OrasTarget() oras.ReadOnlyTarget                  { return nil }
func (m *mockGadgetContext) ReleaseOrasTarget()                               {}
func (m *mockGadgetContext) IsRemoteCall() bool                               { return false }
func (m *mockGadgetContext) IsClient() bool                                   { return false }

func TestPreStart_NoAnnotations(t *testing.T) {
	// Create a datasource with no annotations
	ds, err := datasource.New(datasource.TypeSingle, "test-ds")
	require.NoError(t, err)

	fooField, err := ds.AddField("foo", api.Kind_String)
	require.NoError(t, err)

	barField, err := ds.AddField("bar", api.Kind_Int32)
	require.NoError(t, err)

	exporter := &mockExporter{}
	processor := sdklog.NewSimpleProcessor(exporter)
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(processor))
	logger := provider.Logger("test-logger")

	inst := &otelLogsOperatorInstance{
		loggers: map[datasource.DataSource]otellog.Logger{
			ds: logger,
		},
	}

	gadgetCtx := &mockGadgetContext{
		ctx: context.Background(),
		dataSources: map[string]datasource.DataSource{
			"test-ds": ds,
		},
	}

	err = inst.PreStart(gadgetCtx)
	require.NoError(t, err)

	// Emit data
	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)

	err = fooField.PutString(packet, "hello")
	require.NoError(t, err)
	err = barField.PutInt32(packet, 42)
	require.NoError(t, err)

	err = ds.EmitAndRelease(packet)
	require.NoError(t, err)

	// Verify
	require.Len(t, exporter.records, 1)
	rec := exporter.records[0]

	// Check body is empty (fallback behavior)
	assert.Equal(t, attribute.StringValue(""), rec.Body())

	// Check attributes (fallback behavior: all fields as attributes)
	attrMap := make(map[string]attribute.Value)
	rec.WalkAttributes(func(kv attribute.KeyValue) bool {
		attrMap[string(kv.Key)] = kv.Value
		return true
	})

	require.Contains(t, attrMap, "foo")
	assert.Equal(t, attribute.StringValue("hello"), attrMap["foo"])

	require.Contains(t, attrMap, "bar")
	// Int32 is converted to Int64Value
	assert.Equal(t, attribute.Int64Value(42), attrMap["bar"])
}

func TestPreStart_WithAnnotations(t *testing.T) {
	// Create a datasource with annotations
	ds, err := datasource.New(datasource.TypeSingle, "test-ds")
	require.NoError(t, err)

	// Field with logs.name annotation
	fooField, err := ds.AddField("foo", api.Kind_String)
	require.NoError(t, err)
	fooField.AddAnnotation("logs.name", "custom.foo")

	// Field without annotation should be ignored when other fields are explicitly annotated.
	// The fallback mechanism (adding all fields) is disabled when at least one field is annotated.
	barField, err := ds.AddField("bar", api.Kind_Int32)
	require.NoError(t, err)

	exporter := &mockExporter{}
	processor := sdklog.NewSimpleProcessor(exporter)
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(processor))
	logger := provider.Logger("test-logger")

	inst := &otelLogsOperatorInstance{
		loggers: map[datasource.DataSource]otellog.Logger{
			ds: logger,
		},
	}

	gadgetCtx := &mockGadgetContext{
		ctx: context.Background(),
		dataSources: map[string]datasource.DataSource{
			"test-ds": ds,
		},
	}

	err = inst.PreStart(gadgetCtx)
	require.NoError(t, err)

	// Emit data
	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)

	err = fooField.PutString(packet, "hello")
	require.NoError(t, err)
	err = barField.PutInt32(packet, 42)
	require.NoError(t, err)

	err = ds.EmitAndRelease(packet)
	require.NoError(t, err)

	// Verify
	require.Len(t, exporter.records, 1)
	rec := exporter.records[0]

	// Check body is empty (default if not set)
	assert.Equal(t, attribute.StringValue(""), rec.Body())

	// Check attributes
	attrMap := make(map[string]attribute.Value)
	rec.WalkAttributes(func(kv attribute.KeyValue) bool {
		attrMap[string(kv.Key)] = kv.Value
		return true
	})

	// "custom.foo" should be present
	require.Contains(t, attrMap, "custom.foo")
	assert.Equal(t, attribute.StringValue("hello"), attrMap["custom.foo"])

	// "bar" should NOT be present because we have at least one annotated field, so fallback is disabled.
	require.NotContains(t, attrMap, "bar")
}

func TestPreStart_BodyAnnotation(t *testing.T) {
	// Create a datasource with logs.body annotation
	ds, err := datasource.New(datasource.TypeSingle, "test-ds")
	require.NoError(t, err)
	ds.AddAnnotation("logs.body", "foo") // Use field 'foo' as body

	fooField, err := ds.AddField("foo", api.Kind_String)
	require.NoError(t, err)

	barField, err := ds.AddField("bar", api.Kind_Int32)
	require.NoError(t, err)

	exporter := &mockExporter{}
	processor := sdklog.NewSimpleProcessor(exporter)
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(processor))
	logger := provider.Logger("test-logger")

	inst := &otelLogsOperatorInstance{
		loggers: map[datasource.DataSource]otellog.Logger{
			ds: logger,
		},
	}

	gadgetCtx := &mockGadgetContext{
		ctx: context.Background(),
		dataSources: map[string]datasource.DataSource{
			"test-ds": ds,
		},
	}

	err = inst.PreStart(gadgetCtx)
	require.NoError(t, err)

	// Emit data
	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)

	err = fooField.PutString(packet, "body-content")
	require.NoError(t, err)
	err = barField.PutInt32(packet, 42)
	require.NoError(t, err)

	err = ds.EmitAndRelease(packet)
	require.NoError(t, err)

	// Verify
	require.Len(t, exporter.records, 1)
	rec := exporter.records[0]

	// Check body is set
	assert.Equal(t, attribute.StringValue("body-content"), rec.Body())

	// Check attributes
	attrMap := make(map[string]attribute.Value)
	rec.WalkAttributes(func(kv attribute.KeyValue) bool {
		attrMap[string(kv.Key)] = kv.Value
		return true
	})

	// No fields are annotated with logs.name, but logs.body is set.
	// The fallback mechanism (adding all fields) is disabled when the body is explicitly set.
	// Therefore, no attributes should be present.

	require.Empty(t, attrMap)
}

func TestPreStart_BytesField(t *testing.T) {
	// Create a datasource with a bytes field and no annotations
	ds, err := datasource.New(datasource.TypeSingle, "test-ds-bytes")
	require.NoError(t, err)

	fooField, err := ds.AddField("foo", api.Kind_Bytes)
	require.NoError(t, err)

	exporter := &mockExporter{}
	processor := sdklog.NewSimpleProcessor(exporter)
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(processor))
	logger := provider.Logger("test-logger")

	inst := &otelLogsOperatorInstance{
		loggers: map[datasource.DataSource]otellog.Logger{
			ds: logger,
		},
	}

	gadgetCtx := &mockGadgetContext{
		ctx: context.Background(),
		dataSources: map[string]datasource.DataSource{
			"test-ds-bytes": ds,
		},
	}

	err = inst.PreStart(gadgetCtx)
	require.NoError(t, err)

	// Emit data
	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)

	err = fooField.PutBytes(packet, []byte("hello-bytes"))
	require.NoError(t, err)

	err = ds.EmitAndRelease(packet)
	require.NoError(t, err)

	// Verify
	require.Len(t, exporter.records, 1)
	rec := exporter.records[0]

	// Check body is empty (fallback behavior)
	assert.Equal(t, attribute.StringValue(""), rec.Body())

	// Check attributes (fallback behavior: all fields as attributes)
	attrMap := make(map[string]attribute.Value)
	rec.WalkAttributes(func(kv attribute.KeyValue) bool {
		attrMap[string(kv.Key)] = kv.Value
		return true
	})

	require.Contains(t, attrMap, "foo")
	// Bytes are preserved as BytesValue
	assert.Equal(t, attribute.ByteSliceValue([]byte("hello-bytes")), attrMap["foo"])
}

func TestPreStart_BoolField(t *testing.T) {
	// Create a datasource with a bool field and no annotations
	ds, err := datasource.New(datasource.TypeSingle, "test-ds-bool")
	require.NoError(t, err)

	flagField, err := ds.AddField("flag", api.Kind_Bool)
	require.NoError(t, err)

	exporter := &mockExporter{}
	processor := sdklog.NewSimpleProcessor(exporter)
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(processor))
	logger := provider.Logger("test-logger")

	inst := &otelLogsOperatorInstance{
		loggers: map[datasource.DataSource]otellog.Logger{
			ds: logger,
		},
	}

	gadgetCtx := &mockGadgetContext{
		ctx: context.Background(),
		dataSources: map[string]datasource.DataSource{
			"test-ds-bool": ds,
		},
	}

	err = inst.PreStart(gadgetCtx)
	require.NoError(t, err)

	// Emit data
	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)

	err = flagField.PutBool(packet, true)
	require.NoError(t, err)

	err = ds.EmitAndRelease(packet)
	require.NoError(t, err)

	// Verify
	require.Len(t, exporter.records, 1)
	rec := exporter.records[0]

	// Check body is empty (fallback behavior)
	assert.Equal(t, attribute.StringValue(""), rec.Body())

	// Check attributes (fallback behavior: all fields as attributes)
	attrMap := make(map[string]attribute.Value)
	rec.WalkAttributes(func(kv attribute.KeyValue) bool {
		attrMap[string(kv.Key)] = kv.Value
		return true
	})

	require.Contains(t, attrMap, "flag")
	assert.Equal(t, attribute.BoolValue(true), attrMap["flag"])
}

func TestPreStart_ParentWithChildren_NotEmitted(t *testing.T) {
	// Create a datasource where `parent` is a container with children.
	ds, err := datasource.New(datasource.TypeSingle, "test-parent")
	require.NoError(t, err)

	parent, err := ds.AddField("proc", api.Kind_Invalid, datasource.WithFlags(datasource.FieldFlagContainer|datasource.FieldFlagEmpty))
	require.NoError(t, err)

	_, err = parent.AddSubField("comm", api.Kind_String)
	require.NoError(t, err)
	_, err = parent.AddSubField("pid", api.Kind_Int32)
	require.NoError(t, err)

	// Also add a sibling field to ensure fallback still works for unrelated fields.
	other, err := ds.AddField("other", api.Kind_String)
	require.NoError(t, err)

	exporter := &mockExporter{}
	processor := sdklog.NewSimpleProcessor(exporter)
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(processor))
	l := provider.Logger("test-logger")

	inst := &otelLogsOperatorInstance{
		loggers: map[datasource.DataSource]otellog.Logger{
			ds: l,
		},
	}

	gadgetCtx := &mockGadgetContext{
		ctx: context.Background(),
		dataSources: map[string]datasource.DataSource{
			"test-parent": ds,
		},
	}

	err = inst.PreStart(gadgetCtx)
	require.NoError(t, err)

	// Emit data: set child fields and the sibling field
	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)

	// Set children via parent accessor
	commAcc := ds.GetField("proc.comm")
	require.NotNil(t, commAcc)
	pidAcc := ds.GetField("proc.pid")
	require.NotNil(t, pidAcc)

	require.NoError(t, commAcc.PutString(packet, "sh"))
	require.NoError(t, pidAcc.PutInt32(packet, 1234))
	require.NoError(t, other.PutString(packet, "hello"))

	require.NoError(t, ds.EmitAndRelease(packet))

	// Verify: exporter should contain a record with attributes for children and sibling, but not the parent 'proc'
	require.Len(t, exporter.records, 1)
	rec := exporter.records[0]

	attrMap := make(map[string]attribute.Value)
	rec.WalkAttributes(func(kv attribute.KeyValue) bool {
		attrMap[string(kv.Key)] = kv.Value
		return true
	})

	// children should be present
	require.Contains(t, attrMap, "proc.comm")
	require.Contains(t, attrMap, "proc.pid")
	// parent should NOT be present
	require.NotContains(t, attrMap, "proc")
	// sibling should be present
	require.Contains(t, attrMap, "other")
}

// Retaining an exported record must not retain a caller's mutable byte buffer.
func TestCopyBytesToLogValueOwnsBuffer(t *testing.T) {
	input := []byte{0, 255, 42}
	value := copyBytesToLogValue(input)
	input[0] = 99
	require.Equal(t, []byte{0, 255, 42}, value.AsByteSlice())
	require.Equal(t, attribute.BYTESLICE, value.Type())
}

type wireLogCollector struct {
	collectorlogs.UnimplementedLogsServiceServer
	requests chan *collectorlogs.ExportLogsServiceRequest
}

func (s *wireLogCollector) Export(_ context.Context, request *collectorlogs.ExportLogsServiceRequest) (*collectorlogs.ExportLogsServiceResponse, error) {
	s.requests <- request
	return &collectorlogs.ExportLogsServiceResponse{}, nil
}

// Assert OTLP protobuf kinds, not SDK value internals: upgrading the SDK must
// not turn binary data into strings or booleans into numeric attributes.
func TestPreStart_OTLPWireKinds(t *testing.T) {
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	collector := &wireLogCollector{requests: make(chan *collectorlogs.ExportLogsServiceRequest, 1)}
	collectorlogs.RegisterLogsServiceServer(server, collector)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	conn, err := grpc.NewClient("passthrough:///in-memory-otel", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	require.NoError(t, err)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exporter, err := otlploggrpc.New(ctx, otlploggrpc.WithGRPCConn(conn))
	require.NoError(t, err)
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(exporter)))
	defer func() { require.NoError(t, provider.Shutdown(ctx)) }()
	ds, err := datasource.New(datasource.TypeSingle, "wire")
	require.NoError(t, err)
	ds.AddAnnotation(AnnotationLogsSeverity, "13")
	text, err := ds.AddField("text", api.Kind_String)
	require.NoError(t, err)
	integer, err := ds.AddField("integer", api.Kind_Int64)
	require.NoError(t, err)
	floating, err := ds.AddField("floating", api.Kind_Float64)
	require.NoError(t, err)
	flag, err := ds.AddField("flag", api.Kind_Bool)
	require.NoError(t, err)
	binaryField, err := ds.AddField("binary", api.Kind_Bytes)
	require.NoError(t, err)
	inst := &otelLogsOperatorInstance{loggers: map[datasource.DataSource]otellog.Logger{ds: provider.Logger("wire-test")}}
	require.NoError(t, inst.PreStart(&mockGadgetContext{ctx: ctx, dataSources: map[string]datasource.DataSource{"wire": ds}}))
	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)
	require.NoError(t, text.PutString(packet, "hello"))
	require.NoError(t, integer.PutInt64(packet, -42))
	require.NoError(t, floating.PutFloat64(packet, 1.25))
	require.NoError(t, flag.PutBool(packet, true))
	require.NoError(t, binaryField.PutBytes(packet, []byte{0, 255, 42}))
	require.NoError(t, ds.EmitAndRelease(packet))
	var request *collectorlogs.ExportLogsServiceRequest
	select {
	case request = <-collector.requests:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.Len(t, request.ResourceLogs, 1)
	require.Len(t, request.ResourceLogs[0].ScopeLogs, 1)
	records := request.ResourceLogs[0].ScopeLogs[0].LogRecords
	require.Len(t, records, 1)
	require.EqualValues(t, 13, records[0].SeverityNumber)
	require.Equal(t, &commonpb.AnyValue_StringValue{StringValue: ""}, records[0].Body.Value)
	attrs := map[string]*commonpb.AnyValue{}
	for _, kv := range records[0].Attributes {
		attrs[kv.Key] = kv.Value
	}
	require.Equal(t, &commonpb.AnyValue_StringValue{StringValue: "hello"}, attrs["text"].Value)
	require.Equal(t, &commonpb.AnyValue_IntValue{IntValue: -42}, attrs["integer"].Value)
	require.Equal(t, &commonpb.AnyValue_DoubleValue{DoubleValue: 1.25}, attrs["floating"].Value)
	require.Equal(t, &commonpb.AnyValue_BoolValue{BoolValue: true}, attrs["flag"].Value)
	require.Equal(t, &commonpb.AnyValue_BytesValue{BytesValue: []byte{0, 255, 42}}, attrs["binary"].Value)
}
