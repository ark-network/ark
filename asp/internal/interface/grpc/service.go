package grpcservice

import (
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	appconfig "github.com/ark-network/ark/internal/app-config"
	interfaces "github.com/ark-network/ark/internal/interface"
	"github.com/ark-network/ark/internal/interface/grpc/handlers"
	"github.com/ark-network/ark/internal/interface/grpc/interceptors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type service struct {
	config    Config
	appConfig *appconfig.Config
	server    *grpc.Server
}

func NewService(
	svcConfig Config, appConfig *appconfig.Config,
) (interfaces.Service, error) {
	if err := svcConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid service config: %s", err)
	}
	if err := appConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid app config: %s", err)
	}

	grpcConfig := []grpc.ServerOption{
		interceptors.UnaryInterceptor(), interceptors.StreamInterceptor(),
	}
	if !svcConfig.NoTLS {
		return nil, fmt.Errorf("tls termination not supported yet")
	}
	creds := insecure.NewCredentials()
	grpcConfig = append(grpcConfig, grpc.Creds(creds))
	server := grpc.NewServer(grpcConfig...)
	handler := handlers.NewHandler(appConfig.AppService())
	arkv1.RegisterArkServiceServer(server, handler)
	return &service{svcConfig, appConfig, server}, nil
}

func (s *service) Start() error {
	// nolint:all
	go s.server.Serve(s.config.listener())
	log.Infof("started listening at %s", s.config.address())

	if err := s.appConfig.AppService().Start(); err != nil {
		return fmt.Errorf("failed to start app service: %s", err)
	}
	log.Info("started app service")
	return nil
}

func (s *service) Stop() {
	s.server.Stop()
	log.Info("stopped grpc server")
	s.appConfig.AppService().Stop()
	log.Info("stopped app service")
}
