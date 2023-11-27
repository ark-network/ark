package main

import (
	"os"
	"os/signal"
	"syscall"
	
	log "github.com/sirupsen/logrus"
	service_interface "github.com/ark-network/ark/internal/interface"
)

//nolint:all
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// TODO: Edit this file to something more meaningful for your application.
func main() {
	svc, err := service_interface.NewService()
	if err != nil {
		log.Fatal(err)
	}

	log.RegisterExitHandler(svc.Stop)
	
	log.Info("starting service...")
	if err := svc.Start(); err != nil {
		log.Fatal(err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	<-sigChan

	log.Info("shutting down service...")
	log.Exit(0)
}
	