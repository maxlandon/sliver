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
	"encoding/json"
	"errors"
	"io"
	"time"

	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	"github.com/reeflective/team/client"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
)

const (
	kb = 1024
	mb = kb * 1024
	gb = mb * 1024

	// ClientMaxReceiveMessageSize - Max gRPC message size ~2Gb.
	ClientMaxReceiveMessageSize = (2 * gb) - 1 // 2Gb - 1 byte

	defaultTimeout = 10 * time.Second
)

// ErrNoTLSCredentials is an error raised if the teamclient was asked to setup, or try
// connecting with, TLS credentials. If such an error is raised, make sure your team
// client has correctly fetched -using client.Config()- a remote teamserver config.
var ErrNoTLSCredentials = errors.New("the Teamclient has no TLS credentials to use")

// TokenAuth extracts authentication metadata from contexts,
// specifically the "Authorization": "Bearer" key:value pair.
type TokenAuth string

// init installs the process-global gRPC logger exactly once, at startup, before
// any gRPC server or client is created. gRPC's global logger (grpclog.SetLoggerV2,
// which grpc_logrus.ReplaceGrpcLogger wraps) is explicitly not concurrency-safe and
// must be set before first use; doing it later — as the previous per-dial call did —
// raced the single-player teamserver's running Serve loop (see tests/teamserver).
//
// It is set to a discarding logger, matching this package's existing nil-logger
// default and keeping gRPC's noisy library internals out of the operator console.
// Per-RPC activity is still logged by the grpc_logrus interceptors on both ends.
func init() {
	discard := logrus.New()
	discard.SetOutput(io.Discard)
	grpc_logrus.ReplaceGrpcLogger(logrus.NewEntry(discard))
}

// LogMiddlewareOptions is an example list of gRPC options with logging middleware set up.
// The reeflective/team core now emits slog, but the grpc_logrus middleware requires a
// *logrus.Entry, so the caller (eg. the Sliver console) injects a logrus logger. If none
// is provided, a no-op logger discarding all output is used.
func LogMiddlewareOptions(logger *logrus.Logger) []grpc.DialOption {
	if logger == nil {
		logger = logrus.New()
		logger.SetOutput(io.Discard)
	}

	logrusEntry := logrus.NewEntry(logger)
	logrusOpts := []grpc_logrus.Option{
		grpc_logrus.WithLevels(codeToLevel),
	}

	// NOTE: the process-global gRPC logger is installed once in init() below, not
	// here. Setting it per-dial is a data race: gRPC's global logger is not
	// concurrency-safe, and in single-player mode this call executed while the
	// in-process teamserver's Serve loop was already reading that same global.

	// Intercepting client requests.
	requestIntercept := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		rawRequest, err := json.Marshal(req)
		if err != nil {
			logrusEntry.Errorf("Failed to serialize: %s", err)
			return invoker(ctx, method, req, reply, cc, opts...)
		}

		logrusEntry.Debugf("Raw request: %s", string(rawRequest))

		return invoker(ctx, method, req, reply, cc, opts...)
	}

	options := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithUnaryInterceptor(grpc_logrus.UnaryClientInterceptor(logrusEntry, logrusOpts...)),
		grpc.WithUnaryInterceptor(requestIntercept),
	}

	return options
}

// TLSAuthMiddleware returns the TLS credentials and token authentication options
// built from a given team.Client and its active (target) remote server configuration.
func TLSAuthMiddleware(cli *client.Client) ([]grpc.DialOption, error) {
	config := cli.Config()
	if config.PrivateKey == "" {
		return nil, ErrNoTLSCredentials
	}

	tlsConfig, err := cli.NewTLSConfigFrom(config.CACertificate, config.Certificate, config.PrivateKey)
	if err != nil {
		return nil, err
	}

	transportCreds := credentials.NewTLS(tlsConfig)
	callCreds := credentials.PerRPCCredentials(TokenAuth(config.Token))

	return []grpc.DialOption{
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithPerRPCCredentials(callCreds),
	}, nil
}

// Return value is mapped to request headers.
func (t TokenAuth) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{
		"Authorization": "Bearer " + string(t),
	}, nil
}

// RequireTransportSecurity always return true.
func (TokenAuth) RequireTransportSecurity() bool {
	return true
}

// Maps a grpc response code to a logging level
func codeToLevel(code codes.Code) logrus.Level {
	switch code {
	case codes.OK:
		return logrus.InfoLevel
	case codes.Canceled:
		return logrus.InfoLevel
	case codes.Unknown:
		return logrus.ErrorLevel
	case codes.InvalidArgument:
		return logrus.InfoLevel
	case codes.DeadlineExceeded:
		return logrus.WarnLevel
	case codes.NotFound:
		return logrus.InfoLevel
	case codes.AlreadyExists:
		return logrus.InfoLevel
	case codes.PermissionDenied:
		return logrus.WarnLevel
	case codes.Unauthenticated:
		return logrus.InfoLevel
	case codes.ResourceExhausted:
		return logrus.WarnLevel
	case codes.FailedPrecondition:
		return logrus.WarnLevel
	case codes.Aborted:
		return logrus.WarnLevel
	case codes.OutOfRange:
		return logrus.WarnLevel
	case codes.Unimplemented:
		return logrus.ErrorLevel
	case codes.Internal:
		return logrus.ErrorLevel
	case codes.Unavailable:
		return logrus.WarnLevel
	case codes.DataLoss:
		return logrus.ErrorLevel
	default:
		return logrus.ErrorLevel
	}
}
