package transport

/*
   Sliver Implant Framework
   Copyright (C) 2019  Bishop Fox

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestRecoveryUnaryInterceptorContainsPanic proves the outermost recovery
// interceptor turns a handler panic into a codes.Internal error instead of
// letting it unwind and crash the teamserver process (the failure mode that a
// non-3-part version once triggered via GetVersion).
func TestRecoveryUnaryInterceptorContainsPanic(t *testing.T) {
	interceptor := recoveryUnaryServerInterceptor()

	panicking := func(context.Context, interface{}) (interface{}, error) {
		var s []int
		_ = s[1] // index out of range — same class of bug as the GetVersion crash
		return "unreachable", nil
	}

	resp, err := interceptor(
		context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/rpcpb.SliverRPC/Panics"},
		panicking,
	)

	if resp != nil {
		t.Errorf("expected nil response after recovered panic, got %#v", resp)
	}
	if err == nil {
		t.Fatal("expected an error after recovered panic, got nil (panic escaped?)")
	}
	if code := status.Code(err); code != codes.Internal {
		t.Fatalf("expected codes.Internal, got %s (%v)", code, err)
	}
}

// TestRecoveryUnaryInterceptorPassesThrough confirms the interceptor is
// transparent when the handler does not panic.
func TestRecoveryUnaryInterceptorPassesThrough(t *testing.T) {
	interceptor := recoveryUnaryServerInterceptor()

	ok := func(context.Context, interface{}) (interface{}, error) {
		return "ok", nil
	}

	resp, err := interceptor(
		context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/rpcpb.SliverRPC/GetVersion"},
		ok,
	)
	if err != nil {
		t.Fatalf("unexpected error from non-panicking handler: %s", err)
	}
	if resp != "ok" {
		t.Fatalf("expected passthrough response %q, got %#v", "ok", resp)
	}
}
