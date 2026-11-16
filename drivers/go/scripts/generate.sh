#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Regenerates the checked-in code of the Go driver (go-driver.md §2):
#   internal/pb/rustegon/v1/*.pb.go   gRPC/protobuf stubs from proto/ (buf, no protoc needed)
#   errorcodes_gen.go                 error-code table from drivers/conformance/generated/errors.json
# The tool versions are pinned so that a regeneration on another machine gives the same bytes;
# protoc-gen-go must match google.golang.org/protobuf in go.mod.
set -euo pipefail
cd "$(dirname "$0")/.."
BUF=github.com/bufbuild/buf/cmd/buf@v1.75.0
GEN_GO=google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
GEN_GRPC=google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
bin="$(go env GOPATH)/bin"
for tool in "$BUF" "$GEN_GO" "$GEN_GRPC"; do go install "$tool"; done
export PATH="$bin:$PATH"
rm -rf internal/pb
buf generate ../../proto --template buf.gen.yaml
go run ./internal/cmd/generrors ../conformance/generated/errors.json errorcodes_gen.go
gofmt -w errorcodes_gen.go
