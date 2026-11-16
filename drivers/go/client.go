// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

// Package rustegon is the Go driver of Rustegon (go-driver.md, DEC-014): a goroutine-safe
// Client with a connection pool, SCRAM/X.509/API-key authentication, CRUD, queries with the
// structured AST builders, cursors, bulk writes, sessions and transactions, and the shared retry
// policy of the .NET and Java drivers. Documents are package rdoc values.
package rustegon

import (
	"context"
	"sort"
	"sync/atomic"

	"google.golang.org/grpc"

	pb "github.com/rustegon/rustegon/drivers/go/internal/pb/rustegon/v1"
)

// Client is a long-lived, goroutine-safe handle on a Rustegon deployment. Create one per
// application with New and Close it at shutdown.
type Client struct {
	settings Settings
	pool     *pool
	exec     *executor
	closed   atomic.Bool
}

// New builds a client from options (no network I/O: connections and the login happen on the
// first operation). Errors match ErrArgument.
func New(opts ...Option) (*Client, error) {
	s := DefaultSettings()
	for _, o := range opts {
		if o == nil {
			continue
		}
		if err := o(&s); err != nil {
			return nil, err
		}
	}
	s.Endpoints = append([]string(nil), s.Endpoints...)
	if err := s.validate(); err != nil {
		return nil, err
	}
	p, err := newPool(&s)
	if err != nil {
		return nil, err
	}
	c := &Client{settings: s, pool: p}
	c.exec = &executor{pool: p, auth: &authenticator{cred: s.Credential, settings: &c.settings}, settings: &c.settings}
	return c, nil
}

// Settings returns a copy of the effective settings.
func (c *Client) Settings() Settings {
	s := c.settings
	s.Endpoints = append([]string(nil), s.Endpoints...)
	return s
}

// Close logs out (best effort) and closes the connections. It is idempotent.
func (c *Client) Close(ctx context.Context) error {
	if c.closed.Swap(true) {
		return nil
	}
	c.exec.closed.Store(true)
	_ = ctx
	c.exec.auth.logout(c.pool.slots[0].conn)
	c.pool.close()
	return nil
}

// connect authenticates eagerly (conformance `open`): a bad credential fails here.
func (c *Client) connect(ctx context.Context) error {
	if err := c.exec.checkOpen(); err != nil {
		return err
	}
	_, err := c.exec.auth.authorization(ctx, c.pool.slots[0].conn)
	return mapError(ctx, err)
}

// Ping checks that the server answers.
func (c *Client) Ping(ctx context.Context) error {
	return c.exec.unary(ctx, callSpec{kind: opRead}, func(ctx context.Context, cc grpc.ClientConnInterface, o ...grpc.CallOption) error {
		_, err := pb.NewSessionServiceClient(cc).Ping(ctx, &pb.PingRequest{}, o...)
		return err
	})
}

// ServerInfo describes the server.
type ServerInfo struct {
	ServerVersion   string
	ProtocolVersion string
	Features        []string
	NodeAddresses   []string
}

// ServerInfo returns the server version, protocol version and features.
func (c *Client) ServerInfo(ctx context.Context) (ServerInfo, error) {
	var r *pb.GetServerInfoResponse
	err := c.exec.unary(ctx, callSpec{kind: opRead}, func(ctx context.Context, cc grpc.ClientConnInterface, o ...grpc.CallOption) (err error) {
		r, err = pb.NewSessionServiceClient(cc).GetServerInfo(ctx, &pb.GetServerInfoRequest{}, o...)
		return err
	})
	if err != nil {
		return ServerInfo{}, err
	}
	return ServerInfo{r.GetServerVersion(), r.GetProtocolVersion(), append([]string{}, r.GetFeatures()...), append([]string{}, r.GetNodeAddresses()...)}, nil
}

// Database returns a handle on a database; "" names the default database of the settings.
func (c *Client) Database(name string) *Database {
	if name == "" {
		name = c.settings.DefaultDatabase
	}
	return &Database{ctx: dataContext{exec: c.exec, database: name}}
}

// ListDatabaseNames returns the database names, sorted.
func (c *Client) ListDatabaseNames(ctx context.Context) ([]string, error) {
	var r *pb.ListDatabasesResponse
	err := c.exec.unary(ctx, callSpec{kind: opRead}, func(ctx context.Context, cc grpc.ClientConnInterface, o ...grpc.CallOption) (err error) {
		r, err = pb.NewSchemaServiceClient(cc).ListDatabases(ctx, &pb.ListDatabasesRequest{}, o...)
		return err
	})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(r.GetDatabases()))
	for _, d := range r.GetDatabases() {
		names = append(names, d.GetName())
	}
	sort.Strings(names)
	return names, nil
}

// CreateDatabase creates a database (IfNotExists: no error when it exists). DDL is never
// retried alone (R7): a lost reply would turn the retry into RGN-1031.
func (c *Client) CreateDatabase(ctx context.Context, name string, opts ...OpOption) (bool, error) {
	if name == "" {
		return false, argumentError("empty database name")
	}
	o := collect(opts)
	var r *pb.CreateDatabaseResponse
	err := c.exec.unary(ctx, callSpec{kind: opNoRetry, timeout: o.timeout}, func(ctx context.Context, cc grpc.ClientConnInterface, co ...grpc.CallOption) (err error) {
		r, err = pb.NewSchemaServiceClient(cc).CreateDatabase(ctx, &pb.CreateDatabaseRequest{Name: name, IfNotExists: o.ifNotExists}, co...)
		return err
	})
	return r.GetCreated(), err
}

// DropDatabase drops a database (IfExists: no error when it does not exist).
func (c *Client) DropDatabase(ctx context.Context, name string, opts ...OpOption) (bool, error) {
	if name == "" {
		return false, argumentError("empty database name")
	}
	o := collect(opts)
	var r *pb.DropDatabaseResponse
	err := c.exec.unary(ctx, callSpec{kind: opNoRetry, timeout: o.timeout}, func(ctx context.Context, cc grpc.ClientConnInterface, co ...grpc.CallOption) (err error) {
		r, err = pb.NewSchemaServiceClient(cc).DropDatabase(ctx, &pb.DropDatabaseRequest{Name: name, IfExists: o.ifExists}, co...)
		return err
	})
	return r.GetDropped(), err
}

// StartSession starts a causally consistent session (CausalConsistency(false) to disable).
func (c *Client) StartSession(opts ...OpOption) (*Session, error) {
	if err := c.exec.checkOpen(); err != nil {
		return nil, err
	}
	o := collect(opts)
	causal := true
	if o.causal != nil {
		causal = *o.causal
	}
	return &Session{causal: causal}, nil
}

// ChangePassword changes the password of the logged-in user (PD-076).
func (c *Client) ChangePassword(ctx context.Context, currentPassword, newPassword string) error {
	if currentPassword == "" || newPassword == "" {
		return argumentError("empty password")
	}
	req := &pb.ChangePasswordRequest{CurrentPassword: currentPassword, NewPassword: newPassword}
	return c.exec.unary(ctx, callSpec{kind: opWrite}, func(ctx context.Context, cc grpc.ClientConnInterface, o ...grpc.CallOption) error {
		_, err := pb.NewAdminServiceClient(cc).ChangePassword(ctx, req, o...)
		return err
	})
}
