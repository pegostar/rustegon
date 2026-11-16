// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rustegon

import (
	"context"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/rustegon/rustegon/drivers/go/internal/pb/rustegon/v1"
	"github.com/rustegon/rustegon/drivers/go/internal/scram"
)

// refreshMargin renews a session token this long before it expires.
const refreshMargin = 30 * time.Second

// sessionToken is a login result. Secret: it never appears in logs or errors.
type sessionToken struct {
	token     string
	expiresAt time.Time
}

// login is one in-flight or finished login shared by every caller (single flight): a burst of
// calls on a fresh client performs one SCRAM exchange, not one each.
type login struct {
	done  chan struct{}
	token sessionToken
	err   error
}

// authenticator produces the authorization header of a call (protocol.md §8): an API key as is,
// SCRAM and X.509 through a session token obtained with AuthService.Authenticate.
type authenticator struct {
	cred     *Credential
	settings *Settings
	mu       sync.Mutex
	current  *login
}

func (a *authenticator) usesSessions() bool {
	return a.cred != nil && (a.cred.mechanism == MechanismScramSHA256 || a.cred.mechanism == MechanismX509)
}

func (a *authenticator) authorization(ctx context.Context, cc grpc.ClientConnInterface) (string, error) {
	if a.cred == nil {
		return "", nil
	}
	if a.cred.mechanism == MechanismAPIKey {
		return "ApiKey " + a.cred.secret, nil
	}
	a.mu.Lock()
	l := a.current
	if l == nil || l.failedOrExpiring() {
		l = &login{done: make(chan struct{})}
		a.current = l
		go a.run(l, cc)
	}
	a.mu.Unlock()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-l.done:
	}
	if l.err != nil {
		return "", l.err
	}
	return "Bearer " + l.token.token, nil
}

func (l *login) failedOrExpiring() bool {
	select {
	case <-l.done:
		return l.err != nil || (!l.token.expiresAt.IsZero() && time.Until(l.token.expiresAt) <= refreshMargin)
	default:
		return false
	}
}

// run performs the login detached from the caller that started it: other callers share it, so
// one caller's cancellation must not fail theirs. The operation timeout bounds it.
func (a *authenticator) run(l *login, cc grpc.ClientConnInterface) {
	defer close(l.done)
	ctx, cancel := context.WithTimeout(context.Background(), a.settings.OperationTimeout)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, requestIDHeader, newRequestID())
	tok, err := a.handshake(ctx, cc)
	if err != nil {
		l.err = mapError(ctx, err)
		return
	}
	l.token = tok
}

func (a *authenticator) handshake(ctx context.Context, cc grpc.ClientConnInterface) (sessionToken, error) {
	stream, err := pb.NewAuthServiceClient(cc).Authenticate(ctx)
	if err != nil {
		return sessionToken{}, err
	}
	info := &pb.ClientInfo{DriverName: DriverName, DriverVersion: Version, Application: a.settings.ApplicationName}
	if a.cred.mechanism == MechanismX509 {
		if err := stream.Send(&pb.AuthenticateRequest{Mechanism: pb.AuthMechanism_AUTH_MECHANISM_X509, ClientInfo: info}); err != nil {
			return sessionToken{}, recvErr(stream, err)
		}
		done, err := stream.Recv()
		if err != nil {
			return sessionToken{}, err
		}
		_ = stream.CloseSend()
		return a.accept(done.GetSuccess())
	}
	client, err := scram.NewClient(a.cred.user, a.cred.secret)
	if err != nil {
		return sessionToken{}, newError(CodeUnauthenticated, false, "authentication failed: the credential cannot be prepared (SASLprep)")
	}
	if err := stream.Send(&pb.AuthenticateRequest{Mechanism: pb.AuthMechanism_AUTH_MECHANISM_SCRAM_SHA_256, Payload: []byte(client.ClientFirst()), ClientInfo: info}); err != nil {
		return sessionToken{}, recvErr(stream, err)
	}
	challenge, err := stream.Recv()
	if err != nil {
		return sessionToken{}, err
	}
	if challenge.GetChallenge() == nil {
		return sessionToken{}, newError(CodeUnauthenticated, false, "authentication failed: no SCRAM challenge")
	}
	final, err := client.ProcessServerFirst(string(challenge.GetChallenge()))
	if err != nil {
		return sessionToken{}, newError(CodeUnauthenticated, false, "authentication failed: invalid SCRAM challenge")
	}
	if err := stream.Send(&pb.AuthenticateRequest{Payload: []byte(final)}); err != nil {
		return sessionToken{}, recvErr(stream, err)
	}
	done, err := stream.Recv()
	if err != nil {
		return sessionToken{}, err
	}
	if done.GetSuccess() == nil {
		return sessionToken{}, newError(CodeUnauthenticated, false, "authentication failed: no SCRAM success")
	}
	// Mutual authentication: the server proves it knows the stored key before the token is used.
	if err := client.VerifyServerFinal(string(done.GetSuccess().GetServerFinal())); err != nil {
		return sessionToken{}, newError(CodeUnauthenticated, false, "authentication failed: the server signature is invalid")
	}
	_ = stream.CloseSend()
	return a.accept(done.GetSuccess())
}

// recvErr returns the status of a stream whose send failed (the real cause arrives on Recv).
func recvErr(stream grpc.BidiStreamingClient[pb.AuthenticateRequest, pb.AuthenticateResponse], sendErr error) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	return sendErr
}

func (a *authenticator) accept(s *pb.AuthSuccess) (sessionToken, error) {
	if s == nil || s.GetSessionToken() == "" {
		return sessionToken{}, newError(CodeUnauthenticated, false, "authentication failed: the server returned no session token")
	}
	if s.GetMustChangePassword() && !a.settings.AllowPasswordChangeOnly {
		e := newError(CodePermissionDenied, false, "the account must change its password before other operations are allowed (use WithAllowPasswordChangeOnly to change it through this client)")
		e.Class = ClassPasswordChangeRequired
		return sessionToken{}, e
	}
	t := sessionToken{token: s.GetSessionToken()}
	if s.GetExpiresAtUnixMs() > 0 {
		t.expiresAt = time.UnixMilli(s.GetExpiresAtUnixMs())
	}
	return t, nil
}

// invalidate drops the session whose header was authorization (RGN-4005), unless a newer login
// already replaced it.
func (a *authenticator) invalidate(authorization string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if l := a.current; l != nil {
		select {
		case <-l.done:
			if l.err == nil && "Bearer "+l.token.token == authorization {
				a.current = nil
			}
		default:
		}
	}
}

// logout revokes the session, best effort: it expires on its own if the server is gone.
func (a *authenticator) logout(cc grpc.ClientConnInterface) {
	a.mu.Lock()
	l := a.current
	a.current = nil
	a.mu.Unlock()
	if l == nil {
		return
	}
	select {
	case <-l.done:
	default:
		return
	}
	if l.err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+l.token.token, requestIDHeader, newRequestID())
	_, _ = pb.NewAuthServiceClient(cc).Logout(ctx, &pb.LogoutRequest{})
}
