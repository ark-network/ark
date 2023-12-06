package interfaces

import (
	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/internal/core/application"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/ark-network/ark/internal/interface/grpc/handlers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TODO: Edit this file to something more meaningful for your application.
type Service interface {
	Start() error
	Stop()
}

type service struct {
	grpcService arkv1.ArkServiceServer
	grpcServer  *grpc.Server
}

type Options struct {
	ApplicationService application.Service
	RepositoryManager  ports.RepoManager
}

func NewService(opts Options) (Service, error) {
	return &service{
		grpcService: handlers.NewHandler(opts.ApplicationService, opts.RepositoryManager),
	}, nil
}

// Start implements Service.
func (s *service) Start() error {
	creds := insecure.NewCredentials()
	serverOpts := grpc.Creds(creds)
	server := grpc.NewServer(serverOpts)

	arkv1.RegisterArkServiceServer(server, s.grpcService)

	s.grpcServer = server
	return nil
}

// Stop implements Service.
func (s *service) Stop() {
	s.grpcServer.Stop()
}
