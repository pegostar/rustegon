// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rustegon

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"os"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	pb "github.com/rustegon/rustegon/drivers/go/internal/pb/rustegon/v1"
)

const (
	requestIDHeader      = "rgn-request-id"
	causalityTokenHeader = "rgn-causality-token"
	maxMessageSize       = 64 << 20
	backoffBase          = 10 * time.Millisecond
	backoffCap           = time.Second
)

// slot is one HTTP/2 connection to one endpoint; inFlight drives node selection.
type slot struct {
	endpoint string
	conn     *grpc.ClientConn
	inFlight atomic.Int64
}

// pool holds ConnectionsPerEndpoint connections per endpoint (dotnet-driver.md §3).
type pool struct{ slots []*slot }

func newPool(s *Settings) (*pool, error) {
	creds, err := transportCredentials(s)
	if err != nil {
		return nil, err
	}
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}),
		// A failed connection reconnects with exponential backoff capped at 5 s (PD-119).
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           backoff.Config{BaseDelay: 100 * time.Millisecond, Multiplier: 1.6, Jitter: 0.2, MaxDelay: 5 * time.Second},
			MinConnectTimeout: s.ConnectTimeout,
		}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMessageSize), grpc.MaxCallSendMsgSize(maxMessageSize)),
		grpc.WithUserAgent(DriverName + "/" + Version),
	}
	p := &pool{}
	for _, e := range s.Endpoints {
		for i := 0; i < s.ConnectionsPerEndpoint; i++ {
			// passthrough: the endpoint is dialled as written (no resolver-level load balancing;
			// node selection is the pool's job).
			cc, err := grpc.NewClient("passthrough:///"+e, opts...)
			if err != nil {
				p.close()
				return nil, argumentError("endpoint %s: %v", e, err)
			}
			p.slots = append(p.slots, &slot{endpoint: e, conn: cc})
		}
	}
	return p, nil
}

func transportCredentials(s *Settings) (credentials.TransportCredentials, error) {
	if !s.TLSEnabled() {
		return insecure.NewCredentials(), nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.TLS.ServerName}
	if s.TLS.CAFile != "" {
		pem, err := os.ReadFile(s.TLS.CAFile)
		if err != nil {
			return nil, argumentError("cannot read the TLS CA file: %v", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, argumentError("the TLS CA file holds no PEM certificate")
		}
		cfg.RootCAs = roots
	}
	if s.TLS.CertificateFile != "" {
		pair, err := tls.LoadX509KeyPair(s.TLS.CertificateFile, s.TLS.KeyFile)
		if err != nil {
			return nil, argumentError("cannot load the TLS client certificate: %v", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return credentials.NewTLS(cfg), nil
}

// acquire picks a connection by power of two choices on in-flight calls, avoiding the one that
// just failed when there is another.
func (p *pool) acquire(avoid *slot) *slot {
	n := len(p.slots)
	if n == 1 {
		s := p.slots[0]
		s.inFlight.Add(1)
		return s
	}
	pick := func() *slot {
		if avoid == nil {
			return p.slots[randInt(n)]
		}
		i := randInt(n - 1)
		for k, s := range p.slots {
			if s == avoid && i >= k {
				return p.slots[i+1]
			}
		}
		return p.slots[i]
	}
	a, b := pick(), pick()
	if b.inFlight.Load() < a.inFlight.Load() {
		a = b
	}
	a.inFlight.Add(1)
	return a
}

func (p *pool) close() {
	for _, s := range p.slots {
		_ = s.conn.Close()
	}
}

func randInt(n int) int {
	if n <= 1 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// newRequestID returns a UUIDv7: time-ordered, so server logs sort by arrival.
func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	ms := uint64(time.Now().UnixMilli())
	b[0], b[1], b[2], b[3], b[4], b[5] = byte(ms>>40), byte(ms>>32), byte(ms>>24), byte(ms>>16), byte(ms>>8), byte(ms)
	b[6] = b[6]&0x0f | 0x70
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// opKind is the retry class of an operation (retry.yaml R7).
type opKind int

const (
	opRead opKind = iota
	opWrite
	opNoRetry
)

type callSpec struct {
	kind    opKind
	timeout time.Duration
	session *Session
}

// rpc performs one attempt on a connection; opts carry the trailer capture.
type rpc func(ctx context.Context, cc grpc.ClientConnInterface, opts ...grpc.CallOption) error

type executor struct {
	pool     *pool
	auth     *authenticator
	settings *Settings
	closed   atomic.Bool
}

func (x *executor) checkOpen() error {
	if x.closed.Load() {
		return closedError("the client is closed")
	}
	return nil
}

// backoffDelay is full jitter: uniform in [0, min(cap, base * 2^(attempt-1))] (retry.yaml R1).
func backoffDelay(attempt int) time.Duration {
	ceiling := backoffBase << max(0, attempt-1)
	if ceiling > backoffCap || ceiling <= 0 {
		ceiling = backoffCap
	}
	return time.Duration(randInt(int(ceiling/time.Millisecond)+1)) * time.Millisecond
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// attempts carries the per-operation state shared by every attempt: one request id (a resent
// write is deduplicated by the server, protocol.md §5.1) and one deadline (PD-097, R8).
type attempts struct {
	x              *executor
	spec           callSpec
	requestID      string
	deadline       time.Time
	retries        int
	reauthenticate bool
}

func (x *executor) newAttempts(spec callSpec) *attempts {
	t := spec.timeout
	if t <= 0 {
		t = x.settings.OperationTimeout
	}
	return &attempts{x: x, spec: spec, requestID: newRequestID(), deadline: time.Now().Add(t)}
}

func (a *attempts) outgoing(ctx context.Context, authorization string) (context.Context, error) {
	md := metadata.Pairs(requestIDHeader, a.requestID)
	if authorization != "" {
		md.Append("authorization", authorization)
	}
	if s := a.spec.session; s != nil {
		tok, err := s.tokenToSend()
		if err != nil {
			return nil, err
		}
		if tok != "" {
			md.Append(causalityTokenHeader, tok)
		}
	}
	return metadata.NewOutgoingContext(ctx, md), nil
}

// retry decides whether failure is retried and waits the backoff (retry.yaml R1, R2, R5).
func (a *attempts) retry(ctx context.Context, failure error, authorization string) bool {
	var e *Error
	if !errors.As(failure, &e) {
		return false
	}
	if e.Code == CodeSessionExpired {
		// R5: an expired session is cured by a new login, once, outside the budget.
		if a.reauthenticate || !a.x.auth.usesSessions() {
			return false
		}
		a.reauthenticate = true
		a.x.auth.invalidate(authorization)
		return true
	}
	allowed := false
	switch a.spec.kind {
	case opRead:
		allowed = a.x.settings.RetryReads
	case opWrite:
		allowed = a.x.settings.RetryWrites
	}
	if !e.Retryable || !allowed || a.retries >= a.x.settings.MaxRetries {
		return false
	}
	a.retries++
	delay := backoffDelay(a.retries)
	if e.Class == ClassRateLimited && e.RetryAfter > delay {
		delay = e.RetryAfter
	}
	if time.Now().Add(delay).After(a.deadline) {
		return false
	}
	return sleepCtx(ctx, delay) == nil
}

// unary runs a unary or fully consumed call with the retry policy.
func (x *executor) unary(ctx context.Context, spec callSpec, call rpc) error {
	return x.run(ctx, spec, func(ctx context.Context, cc grpc.ClientConnInterface, opts ...grpc.CallOption) (bool, error) {
		return false, call(ctx, cc, opts...)
	})
}

// run is the attempt loop; call reports whether it delivered data before failing (R3: an Execute
// stream that already delivered a batch is not retried).
func (x *executor) run(ctx context.Context, spec callSpec, call func(context.Context, grpc.ClientConnInterface, ...grpc.CallOption) (bool, error)) error {
	if err := x.checkOpen(); err != nil {
		return err
	}
	a := x.newAttempts(spec)
	octx, cancel := context.WithDeadline(ctx, a.deadline)
	defer cancel()
	var failed *slot
	for {
		s := x.pool.acquire(failed)
		authorization, err := x.auth.authorization(octx, s.conn)
		var delivered bool
		if err == nil {
			var cctx context.Context
			cctx, err = a.outgoing(octx, authorization)
			if err == nil {
				var trailer metadata.MD
				delivered, err = call(cctx, s.conn, grpc.Trailer(&trailer))
				if err == nil && spec.session != nil {
					spec.session.observe(trailer)
				}
			}
		}
		s.inFlight.Add(-1)
		if err == nil {
			return nil
		}
		err = mapError(ctx, err)
		failed = s
		if delivered || !a.retry(octx, err, authorization) {
			return err
		}
	}
}

// consistency builds the proto read consistency of an operation from its options and the settings.
func (x *executor) consistency(level ReadConsistency, staleness time.Duration) (*pb.ReadConsistency, error) {
	if level == ServerDefaultConsistency {
		level = x.settings.ReadConsistency
	}
	if level == ServerDefaultConsistency {
		return nil, nil
	}
	if staleness == 0 {
		staleness = x.settings.MaxStaleness
	}
	if level == BoundedStaleness && staleness <= 0 {
		return nil, argumentError("BoundedStaleness needs MaxStaleness")
	}
	if staleness < 0 {
		return nil, argumentError("MaxStaleness must be positive")
	}
	c := &pb.ReadConsistency{}
	switch level {
	case Linearizable:
		c.Level = pb.ReadConsistencyLevel_READ_CONSISTENCY_LEVEL_LINEARIZABLE
	case BoundedStaleness:
		c.Level = pb.ReadConsistencyLevel_READ_CONSISTENCY_LEVEL_BOUNDED_STALENESS
	default:
		c.Level = pb.ReadConsistencyLevel_READ_CONSISTENCY_LEVEL_FOLLOWER
	}
	if level != Linearizable && staleness > 0 {
		ms := uint32(min(int64(^uint32(0)), int64((staleness+time.Millisecond-1)/time.Millisecond)))
		c.MaxStalenessMs = &ms
	}
	return c, nil
}

func (x *executor) concern(wc WriteConcern) pb.WriteConcern {
	if wc == ServerDefaultConcern {
		wc = x.settings.WriteConcern
	}
	switch wc {
	case Majority:
		return pb.WriteConcern_WRITE_CONCERN_MAJORITY
	case All:
		return pb.WriteConcern_WRITE_CONCERN_ALL
	}
	return pb.WriteConcern_WRITE_CONCERN_UNSPECIFIED
}

// drain reads a server stream to its end.
func drain[T any](stream interface{ Recv() (*T, error) }) ([]*T, error) {
	var out []*T
	for {
		m, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, m)
	}
}
