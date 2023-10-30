package grpc_interface

import (
	log "github.com/sirupsen/logrus"
)

// TODO: Edit this file to something more meaningful for your application.
type service struct {}

func NewService() (*service, error) {
	return &service{}, nil
}

func (s *service) Start() error {
	log.Debug("service is listening")
	return nil
}

func (s *service) Stop() {
	log.Debug("service stopped")
}
	