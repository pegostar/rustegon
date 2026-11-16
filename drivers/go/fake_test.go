// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rustegon

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	pb "github.com/rustegon/rustegon/drivers/go/internal/pb/rustegon/v1"
	"github.com/rustegon/rustegon/drivers/go/rdoc"
)

// The in-process fake gRPC server of retry.yaml (README §8, PD-073): scripted replies per RPC,
// defaults for the rest, and a record of every call.

const (
	fakeScramUser     = "fake"
	fakeScramPassword = "fake-password-123"
	fakeTxnID         = "0190f3a4-7b1c-7cc1-8a9e-1d2c3b4a5f60"
)

type fakeCall struct {
	rpc         string
	requestID   string
	hasDeadline bool
	arrival     time.Duration
	replied     time.Duration
	hasReplied  bool
	failed      bool
	// index is the position of the call in the record; repliedBefore is the number of calls
	// recorded when this one was answered. The retry check orders calls by these, not by the
	// timestamps: the monotonic clock of Go on Windows advances in steps of about 0.5 ms, so a
	// retry sent right after a failed reply (full jitter may wait 0 ms) can carry the same
	// timestamp as the reply.
	index         int
	repliedBefore int
}

type fakeServer struct {
	script   map[string][]any
	start    time.Time
	mu       sync.Mutex
	consumed map[string]int
	calls    []*fakeCall
	sessions int
	srv      *grpc.Server
	addr     string
}

func startFake(script *ymap) (*fakeServer, error) {
	f := &fakeServer{script: map[string][]any{}, start: time.Now(), consumed: map[string]int{}}
	if script != nil {
		for _, k := range script.keys {
			f.script[k] = script.list(k)
		}
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f.addr = lis.Addr().String()
	f.srv = grpc.NewServer(grpc.UnknownServiceHandler(f.handle))
	go func() { _ = f.srv.Serve(lis) }()
	return f, nil
}

func (f *fakeServer) stop() { f.srv.Stop() }

func (f *fakeServer) callList() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeCall, len(f.calls))
	for i, c := range f.calls {
		out[i] = *c
	}
	return out
}

func (f *fakeServer) record(ctx context.Context, rpc string) *fakeCall {
	md, _ := metadata.FromIncomingContext(ctx)
	c := &fakeCall{rpc: rpc, arrival: time.Since(f.start)}
	if v := md.Get(requestIDHeader); len(v) > 0 {
		c.requestID = v[0]
	}
	_, c.hasDeadline = ctx.Deadline()
	f.mu.Lock()
	c.index = len(f.calls)
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	return c
}

func (f *fakeServer) done(c *fakeCall, failed bool) {
	f.mu.Lock()
	c.replied, c.hasReplied, c.failed = time.Since(f.start), true, failed
	c.repliedBefore = len(f.calls)
	f.mu.Unlock()
}

func (f *fakeServer) next(rpc string) *ymap {
	f.mu.Lock()
	defer f.mu.Unlock()
	replies := f.script[rpc]
	if len(replies) == 0 {
		return &ymap{vals: map[string]any{}}
	}
	n := f.consumed[rpc]
	f.consumed[rpc] = n + 1
	return replies[min(n, len(replies)-1)].(*ymap)
}

func (f *fakeServer) handle(_ any, stream grpc.ServerStream) error {
	full, _ := grpc.MethodFromServerStream(stream)
	svc, method, _ := strings.Cut(strings.TrimPrefix(full, "/"), "/")
	rpc := strings.TrimPrefix(svc, "rustegon.v1.") + "." + method
	sd, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(svc))
	if err != nil {
		return status.Error(codes.Unimplemented, "unknown service "+svc)
	}
	md := sd.(protoreflect.ServiceDescriptor).Methods().ByName(protoreflect.Name(method))
	if md == nil {
		return status.Error(codes.Unimplemented, "unknown method "+rpc)
	}
	if md.IsStreamingClient() {
		return f.authenticate(stream, rpc)
	}
	in := newMessage(md.Input())
	if err := stream.RecvMsg(in); err != nil {
		return err
	}
	call := f.record(stream.Context(), rpc)
	reply := f.next(rpc)
	if d, ok := reply.get("delayMs").(int64); ok {
		select {
		case <-time.After(time.Duration(d) * time.Millisecond):
		case <-stream.Context().Done():
			// The caller's deadline passed while the reply was delayed: a real server never
			// answers such a call, so neither does the fake (a late OK could win the client's
			// race between the reply and its own deadline on a starved host).
			f.done(call, true)
			return status.FromContextError(stream.Context().Err()).Err()
		}
	}
	if e := reply.mp("error"); e != nil {
		f.done(call, true)
		return errorStatus(e)
	}
	if t := reply.str("transport"); t != "" {
		f.done(call, true)
		return status.Error(parseCode(t), t)
	}
	msgs, err := okMessages(rpc, md, in, reply.get("ok"))
	if err != nil {
		f.done(call, true)
		return status.Error(codes.Internal, err.Error())
	}
	for _, m := range msgs {
		if err := stream.SendMsg(m); err != nil {
			return err
		}
	}
	f.done(call, false)
	return nil
}

func newMessage(d protoreflect.MessageDescriptor) proto.Message {
	t, err := protoregistry.GlobalTypes.FindMessageByName(d.FullName())
	if err != nil {
		panic(err)
	}
	return t.New().Interface()
}

func parseCode(name string) codes.Code {
	for c := codes.OK; c <= codes.Unauthenticated; c++ {
		if strings.EqualFold(strings.ReplaceAll(name, "_", ""), c.String()) {
			return c
		}
	}
	if name == "CANCELLED" {
		return codes.Canceled
	}
	return codes.Unknown
}

func errorStatus(e *ymap) error {
	code := int(e.get("code").(int64))
	entry, ok := catalog[int32(code)]
	if !ok {
		return status.Error(codes.Internal, fmt.Sprintf("unknown code %d", code))
	}
	var trace [16]byte
	_, _ = rand.Read(trace[:])
	d := &pb.ErrorDetail{Code: uint32(code), Name: entry.name, Retryable: e.isTrue("retryable"), TraceId: hex.EncodeToString(trace[:])}
	if b, ok := e.get("committed").(bool); ok {
		d.Committed = &b
	}
	if ms, ok := e.get("retryAfterMs").(int64); ok {
		v := uint32(ms)
		d.RetryAfterMs = &v
	}
	if det := e.mp("details"); det != nil {
		d.Details = map[string]string{}
		for _, k := range det.keys {
			d.Details[k] = fmt.Sprint(det.vals[k])
		}
	}
	st, err := status.New(grpcCodeOf(code), entry.name).WithDetails(d)
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	return st.Err()
}

// grpcCodeOf is the gRPC status of a catalog code (protocol.md §7), via the transport table
// inverted where possible, otherwise by code class.
func grpcCodeOf(code int) codes.Code {
	switch code {
	case 1005, 1031:
		return codes.AlreadyExists
	case 1030, 1021:
		return codes.NotFound
	case 2001, 2002, 2005, 2007, 2008:
		return codes.Aborted
	case 3002, 3004, 3007:
		return codes.Unavailable
	case 4001, 4005, 4007:
		return codes.Unauthenticated
	case 4002:
		return codes.PermissionDenied
	case 4003, 5004:
		return codes.ResourceExhausted
	case 5006, 2003:
		return codes.DeadlineExceeded
	case 2006, 5001:
		return codes.Unknown
	}
	if code < 2000 {
		return codes.InvalidArgument
	}
	return codes.FailedPrecondition
}

func okMessages(rpc string, md protoreflect.MethodDescriptor, in proto.Message, ok any) ([]proto.Message, error) {
	if ok == nil {
		return []proto.Message{defaultReply(rpc, md, in)}, nil
	}
	if rpc == "QueryService.Execute" {
		var out []proto.Message
		for _, b := range ok.(*ymap).list("batches") {
			batch := &pb.ResultBatch{}
			if err := build(batch.ProtoReflect(), b.(*ymap)); err != nil {
				return nil, err
			}
			out = append(out, &pb.ExecuteResponse{Batch: batch})
		}
		return out, nil
	}
	m := newMessage(md.Output())
	if err := build(m.ProtoReflect(), ok.(*ymap)); err != nil {
		return nil, err
	}
	return []proto.Message{m}, nil
}

func defaultReply(rpc string, md protoreflect.MethodDescriptor, in proto.Message) proto.Message {
	switch rpc {
	case "SessionService.GetServerInfo":
		return &pb.GetServerInfoResponse{ServerVersion: "0.0.0-fake", ProtocolVersion: "1.0"}
	case "TransactionService.Begin":
		return &pb.BeginResponse{TxnId: fakeTxnID, HeartbeatIntervalMs: 1000}
	case "TransactionService.Status":
		return &pb.StatusResponse{State: pb.TransactionState_TRANSACTION_STATE_COMMITTED}
	case "DocumentService.Insert":
		r := &pb.InsertResponse{}
		for _, d := range in.(*pb.InsertRequest).GetDocuments() {
			doc, _ := rdoc.DecodeDocument(d.GetRdoc())
			id, ok := doc.Get("_id")
			if !ok {
				id = rdoc.NewObjectID()
			}
			b, _ := rdoc.EncodeValue(id)
			r.Results = append(r.Results, &pb.WriteResult{Id: &pb.Value{RdocValue: b}})
		}
		return r
	case "QueryService.Execute":
		return &pb.ExecuteResponse{Batch: &pb.ResultBatch{}}
	}
	return newMessage(md.Output())
}

// build fills a message from the protobuf JSON mapping, except that Document and Value fields
// are canonical extended JSON (README §8).
func build(m protoreflect.Message, json *ymap) error {
	fields := m.Descriptor().Fields()
	for _, k := range json.keys {
		fd := fields.ByJSONName(k)
		if fd == nil {
			fd = fields.ByName(protoreflect.Name(k))
		}
		if fd == nil {
			return fmt.Errorf("%s has no field %q", m.Descriptor().Name(), k)
		}
		v := json.vals[k]
		if fd.IsList() {
			l := m.Mutable(fd).List()
			for _, item := range v.([]any) {
				pv, err := fieldValue(m, fd, item, l.NewElement)
				if err != nil {
					return err
				}
				l.Append(pv)
			}
			continue
		}
		pv, err := fieldValue(m, fd, v, func() protoreflect.Value { return m.NewField(fd) })
		if err != nil {
			return err
		}
		m.Set(fd, pv)
	}
	return nil
}

func fieldValue(_ protoreflect.Message, fd protoreflect.FieldDescriptor, v any, newElem func() protoreflect.Value) (protoreflect.Value, error) {
	switch fd.Kind() {
	case protoreflect.MessageKind:
		elem := newElem()
		switch fd.Message().FullName() {
		case "rustegon.v1.Document":
			b, err := rdoc.EncodeDocument(toDocument(v.(*ymap), nil))
			if err != nil {
				return protoreflect.Value{}, err
			}
			proto.Merge(elem.Message().Interface(), &pb.Document{Rdoc: b})
		case "rustegon.v1.Value":
			b, err := rdoc.EncodeValue(toValue(v, nil))
			if err != nil {
				return protoreflect.Value{}, err
			}
			proto.Merge(elem.Message().Interface(), &pb.Value{RdocValue: b})
		default:
			if err := build(elem.Message(), v.(*ymap)); err != nil {
				return protoreflect.Value{}, err
			}
		}
		return elem, nil
	case protoreflect.EnumKind:
		ev := fd.Enum().Values().ByName(protoreflect.Name(v.(string)))
		if ev == nil {
			return protoreflect.Value{}, fmt.Errorf("unknown enum value %v", v)
		}
		return protoreflect.ValueOfEnum(ev.Number()), nil
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(fmt.Sprint(v)), nil
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(v.(bool)), nil
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes([]byte(v.(string))), nil
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(uint32(num(v))), nil
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(uint64(num(v))), nil
	case protoreflect.Int32Kind, protoreflect.Sint32Kind:
		return protoreflect.ValueOfInt32(int32(num(v))), nil
	case protoreflect.Int64Kind, protoreflect.Sint64Kind:
		return protoreflect.ValueOfInt64(num(v)), nil
	}
	return protoreflect.Value{}, fmt.Errorf("field kind %v is not supported by the fake server", fd.Kind())
}

func num(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case float64:
		return int64(math.Round(x))
	case string:
		var n int64
		_, _ = fmt.Sscan(x, &n)
		return n
	}
	return 0
}

// authenticate runs the SCRAM-SHA-256 server side for fakeScramUser.
func (f *fakeServer) authenticate(stream grpc.ServerStream, rpc string) error {
	call := f.record(stream.Context(), rpc)
	fail := func() error {
		f.done(call, true)
		return status.Error(codes.Unauthenticated, "fake-authentication-failed")
	}
	first := &pb.AuthenticateRequest{}
	if err := stream.RecvMsg(first); err != nil {
		return fail()
	}
	bare := strings.TrimPrefix(string(first.GetPayload()), "n,,")
	i := strings.Index(bare, ",r=")
	if i < 0 {
		return fail()
	}
	clientNonce := bare[i+3:]
	salt := make([]byte, 16)
	extra := make([]byte, 18)
	_, _ = rand.Read(salt)
	_, _ = rand.Read(extra)
	const iterations = 4096
	serverFirst := fmt.Sprintf("r=%s%s,s=%s,i=%d", clientNonce, base64.StdEncoding.EncodeToString(extra), base64.StdEncoding.EncodeToString(salt), iterations)
	if err := stream.SendMsg(&pb.AuthenticateResponse{Step: &pb.AuthenticateResponse_Challenge{Challenge: []byte(serverFirst)}}); err != nil {
		return err
	}
	final := &pb.AuthenticateRequest{}
	if err := stream.RecvMsg(final); err != nil {
		return fail()
	}
	clientFinal := string(final.GetPayload())
	at := strings.Index(clientFinal, ",p=")
	if at < 0 {
		return fail()
	}
	authMessage := bare + "," + serverFirst + "," + clientFinal[:at]
	salted, err := pbkdf2.Key(sha256.New, fakeScramPassword, salt, iterations, 32)
	if err != nil {
		return fail()
	}
	mac := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	clientKey := mac(salted, "Client Key")
	stored := sha256.Sum256(clientKey)
	sig := mac(stored[:], authMessage)
	proof, err := base64.StdEncoding.DecodeString(clientFinal[at+3:])
	if err != nil || len(proof) != len(sig) {
		return fail()
	}
	for k := range proof {
		proof[k] ^= sig[k]
	}
	if subtle.ConstantTimeCompare(proof, clientKey) != 1 {
		return fail()
	}
	serverSig := mac(mac(salted, "Server Key"), authMessage)
	f.mu.Lock()
	f.sessions++
	n := f.sessions
	f.mu.Unlock()
	success := &pb.AuthSuccess{ServerFinal: []byte("v=" + base64.StdEncoding.EncodeToString(serverSig)),
		SessionToken: fmt.Sprintf("fake-session-%d", n), ExpiresAtUnixMs: time.Now().Add(time.Hour).UnixMilli(), User: fakeScramUser}
	if err := stream.SendMsg(&pb.AuthenticateResponse{Step: &pb.AuthenticateResponse_Success{Success: success}}); err != nil {
		return err
	}
	f.done(call, false)
	return nil
}

// ---------------------------------------------------------------- retry scenarios (TC-DRV-GO-016)

const retryTolerance = 250 * time.Millisecond

func runRetryScenarios(file, only string) error {
	rootAny, err := loadYAML(filepath.Join(conformanceDir(), file))
	if err != nil {
		return err
	}
	root := rootAny.(*ymap)
	for _, sAny := range root.list("scenarios") {
		s := sAny.(*ymap)
		if only != "" && s.str("name") != only {
			continue
		}
		if err := runScenario(root, s); err != nil {
			return fmt.Errorf("%s: %w", s.str("name"), err)
		}
	}
	return nil
}

func runScenario(root, scenario *ymap) error {
	defaults := root.mp("defaults")
	settings := map[string]any{}
	for _, m := range []*ymap{defaults.mp("settings"), scenario.mp("settings")} {
		if m != nil {
			for _, k := range m.keys {
				settings[k] = m.vals[k]
			}
		}
	}
	fake, err := startFake(scenario.mp("server"))
	if err != nil {
		return err
	}
	defer fake.stop()
	cred := APIKeyCredential("rgn_fake_key")
	if scenario.str("credential") == "scram" {
		cred = ScramCredential(fakeScramUser, fakeScramPassword)
	}
	c, err := New(WithEndpoints(fake.addr), WithCredential(cred), WithRetryReads(settings["retryReads"].(bool)),
		WithRetryWrites(settings["retryWrites"].(bool)), WithMaxRetries(int(settings["maxRetries"].(int64))),
		WithOperationTimeout(time.Duration(settings["operationTimeoutMs"].(int64))*time.Millisecond),
		WithDefaultDatabase("fake"), WithConnectionsPerEndpoint(1))
	if err != nil {
		return err
	}
	expect := scenario.mp("expect")
	src := scenario.mp("operation")
	op := &ymap{keys: append([]string(nil), src.keys...), vals: map[string]any{}}
	for k, v := range src.vals {
		op.vals[k] = v
	}
	op.keys = append(op.keys, "expect", "match")
	op.vals["expect"], op.vals["match"] = expect.get("outcome"), "subset"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	r := newRun(ctx, c, "fake", "c", func(s string) string { return s }, "")
	runErr := r.runOps([]any{op}, true)
	r.close()
	_ = c.Close(ctx)
	if runErr != nil {
		return runErr
	}
	calls := fake.callList()
	if want := expect.mp("calls"); want != nil {
		for _, rpc := range want.keys {
			n := 0
			for _, cl := range calls {
				if cl.rpc == rpc {
					n++
				}
			}
			if int64(n) != want.vals[rpc].(int64) {
				var names []string
				for _, cl := range calls {
					names = append(names, cl.rpc)
				}
				return fmt.Errorf("%s called %d times, expected %d; calls: %s", rpc, n, want.vals[rpc], strings.Join(names, ", "))
			}
		}
	}
	for _, rpcAny := range expect.list("sameRequestId") {
		ids := map[string]bool{}
		for _, cl := range calls {
			if cl.rpc == rpcAny.(string) {
				ids[cl.requestID] = true
			}
		}
		if len(ids) != 1 || ids[""] {
			return fmt.Errorf("%s request ids %v", rpcAny, ids)
		}
	}
	if expect.isTrue("grpcTimeoutSent") {
		for _, cl := range calls {
			if cl.rpc != "AuthService.Logout" && !cl.hasDeadline {
				return fmt.Errorf("%s without grpc-timeout", cl.rpc)
			}
		}
	}
	backoff := defaults.mp("backoff")
	var failures []fakeCall
	for _, cl := range calls {
		if cl.failed && cl.hasReplied && cl.rpc != "TransactionService.Rollback" {
			failures = append(failures, cl)
		}
	}
	for _, dAny := range expect.list("delays") {
		d := dAny.(*ymap)
		n := int(d.get("retry").(int64))
		if len(failures) < n {
			return fmt.Errorf("retry %d expected but only %d failures", n, len(failures))
		}
		failed := failures[n-1]
		// The next call is the first one recorded after the failed reply was given (record
		// order is causal; equal timestamps are not, see fakeCall.repliedBefore).
		var next *fakeCall
		for i := failed.repliedBefore; i < len(calls); i++ {
			if rpc := calls[i].rpc; rpc != "TransactionService.Rollback" && rpc != "TransactionService.Heartbeat" {
				next = &calls[i]
				break
			}
		}
		if next == nil {
			return fmt.Errorf("no call after failure %d", n)
		}
		gap := max(0, next.arrival-failed.replied)
		if minMs, ok := d.get("minMs").(int64); ok {
			if gap < time.Duration(minMs)*time.Millisecond {
				return fmt.Errorf("retry %d after %v, expected at least %d ms", n, gap, minMs)
			}
		} else {
			ceiling := math.Min(float64(backoff.get("capMs").(int64)), float64(backoff.get("baseMs").(int64))*math.Pow(float64(backoff.get("factor").(int64)), float64(n-1)))
			if gap > time.Duration(ceiling)*time.Millisecond+retryTolerance {
				return fmt.Errorf("retry %d after %v, expected at most %v ms + tolerance", n, gap, ceiling)
			}
		}
	}
	return nil
}

func TestTCDrvGo016RetryScenarios(t *testing.T) {
	rootAny, err := loadYAML(filepath.Join(conformanceDir(), "retry.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range rootAny.(*ymap).list("scenarios") {
		name := s.(*ymap).str("name")
		// Sequential, as in the conformance runner (TC-DRV-CONF-CLIENT-008): the scenarios assert
		// wall-clock gaps, which concurrent scenarios would distort with their own load.
		t.Run(name, func(t *testing.T) {
			if err := runRetryScenarios("retry.yaml", name); err != nil {
				t.Fatal(err)
			}
		})
	}
}

var _ = errors.New
