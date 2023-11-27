package service_interface

import (
	grpc_interface "github.com/ark-network/ark/internal/interface/grpc"
)

// TODO: Edit this file to something more meaningful for your application.
type Service interface {
	Start() error
	Stop()
}

func NewService() (Service, error) {
	return grpc_interface.NewService()
}
	