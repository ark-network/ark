package grpcservice

import (
	"crypto/tls"
	"fmt"
	"net"
)

type Config struct {
	Port     uint32
	NoTLS    bool
	AuthUser string
	AuthPass string
}

func (c Config) Validate() error {
	if len(c.AuthUser) == 0 {
		return fmt.Errorf("missing auth user")
	}

	if len(c.AuthPass) == 0 {
		return fmt.Errorf("missing auth password")
	}

	lis, err := net.Listen("tcp", c.address())
	if err != nil {
		return fmt.Errorf("invalid port: %s", err)
	}
	defer lis.Close()

	if !c.NoTLS {
		return fmt.Errorf("tls termination not supported yet")
	}
	return nil
}

func (c Config) insecure() bool {
	return c.NoTLS
}

func (c Config) address() string {
	return fmt.Sprintf(":%d", c.Port)
}

func (c Config) gatewayAddress() string {
	return fmt.Sprintf("localhost:%d", c.Port)
}

func (c Config) tlsConfig() *tls.Config {
	return nil
}
