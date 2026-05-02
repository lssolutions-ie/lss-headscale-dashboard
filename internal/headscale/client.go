// Package headscale wraps the Headscale gRPC API.
//
// v0.1.0: dial-only connection test. Verifies that a gRPC server is listening
// at the configured address (unix socket or TCP+TLS) and reaches connectivity
// state READY within the timeout. Real RPC stubs (ListUsers, ListNodes, ...)
// require generating Go code from Headscale's .proto files; that lands when
// protoc is available — see CLAUDE.md.
package headscale

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type Mode string

const (
	ModeSocket Mode = "socket"
	ModeGRPC   Mode = "grpc"
)

type Config struct {
	Mode       Mode
	SocketPath string // for ModeSocket
	Address    string // host:port, for ModeGRPC
	TLS        bool   // for ModeGRPC
	APIKey     string // for ModeGRPC
}

func (c Config) Validate() error {
	switch c.Mode {
	case ModeSocket:
		if strings.TrimSpace(c.SocketPath) == "" {
			return errors.New("socket_path is required for mode=socket")
		}
	case ModeGRPC:
		if strings.TrimSpace(c.Address) == "" {
			return errors.New("address is required for mode=grpc")
		}
		if strings.TrimSpace(c.APIKey) == "" {
			return errors.New("api_key is required for mode=grpc")
		}
	default:
		return fmt.Errorf("unknown mode %q (want socket|grpc)", c.Mode)
	}
	return nil
}

// TestConnection dials Headscale and waits for the channel to become READY.
// Returns nil on success.
func TestConnection(ctx context.Context, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	var (
		target   string
		dialOpts []grpc.DialOption
	)

	switch cfg.Mode {
	case ModeSocket:
		target = "passthrough:///" + cfg.SocketPath
		dialOpts = append(dialOpts,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", addr)
			}),
		)
	case ModeGRPC:
		target = cfg.Address
		if cfg.TLS {
			dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				MinVersion: tls.VersionTLS12,
			})))
		} else {
			dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		}
		// API key is only meaningful once we issue real RPCs; we still verify
		// it is non-empty in Validate(). When the real client lands, attach it
		// via grpc.WithPerRPCCredentials.
	}

	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	conn.Connect()
	for {
		s := conn.GetState()
		if s == connectivity.Ready {
			return nil
		}
		if s == connectivity.TransientFailure || s == connectivity.Shutdown {
			return fmt.Errorf("connection not ready: state=%s", s)
		}
		if !conn.WaitForStateChange(dialCtx, s) {
			return fmt.Errorf("timeout waiting for ready (last state=%s)", s)
		}
	}
}
