package grpcservice

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	appconfig "github.com/ark-network/ark/internal/app-config"
	"github.com/ark-network/ark/internal/core/application"
	interfaces "github.com/ark-network/ark/internal/interface"
	"github.com/ark-network/ark/internal/interface/grpc/handlers"
	"github.com/ark-network/ark/internal/interface/grpc/interceptors"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type service struct {
	config     Config
	appConfig  *appconfig.Config
	server     *http.Server
	grpcServer *grpc.Server
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

	return &service{svcConfig, appConfig, nil, nil}, nil
}

func (s *service) Start() error {
	withoutAppSvc := false
	return s.start(withoutAppSvc)
}

func (s *service) Stop() {
	withAppSvc := true
	s.stop(withAppSvc)
}

func (s *service) start(withAppSvc bool) error {
	if err := s.newServer(withAppSvc); err != nil {
		return err
	}

	if withAppSvc {
		appSvc, _ := s.appConfig.AppService()
		if err := appSvc.Start(); err != nil {
			return fmt.Errorf("failed to start app service: %s", err)
		}
		log.Info("started app service")
	}

	if s.config.insecure() {
		// nolint:all
		go s.server.ListenAndServe()
	} else {
		// nolint:all
		go s.server.ListenAndServeTLS("", "")
	}
	log.Infof("started listening at %s", s.config.address())

	return nil
}

func (s *service) stop(withAppSvc bool) {
	//nolint:all
	s.server.Shutdown(context.Background())
	log.Info("stopped grpc server")
	if withAppSvc {
		appSvc, _ := s.appConfig.AppService()
		if appSvc != nil {
			appSvc.Stop()
			log.Info("stopped app service")
		}
	}
}

func (s *service) newServer(withAppSvc bool) error {
	grpcConfig := []grpc.ServerOption{
		interceptors.UnaryInterceptor(s.config.AuthUser, s.config.AuthPass),
		interceptors.StreamInterceptor(),
	}
	if !s.config.NoTLS {
		return fmt.Errorf("tls termination not supported yet")
	}
	creds := insecure.NewCredentials()
	if !s.config.insecure() {
		creds = credentials.NewTLS(s.config.tlsConfig())
	}
	grpcConfig = append(grpcConfig, grpc.Creds(creds))

	// Server grpc.
	grpcServer := grpc.NewServer(grpcConfig...)

	var appSvc application.Service
	if withAppSvc {
		svc, err := s.appConfig.AppService()
		if err != nil {
			return err
		}
		appSvc = svc
		appHandler := handlers.NewHandler(appSvc)
		arkv1.RegisterArkServiceServer(grpcServer, appHandler)
	}

	adminHandler := handlers.NewAdminHandler(s.appConfig.AdminService(), appSvc)
	arkv1.RegisterAdminServiceServer(grpcServer, adminHandler)

	walletHandler := handlers.NewWalletHandler(s.appConfig.WalletService(), s.onUnlock)
	arkv1.RegisterWalletServiceServer(grpcServer, walletHandler)

	healthHandler := handlers.NewHealthHandler()
	grpchealth.RegisterHealthServer(grpcServer, healthHandler)

	// Creds for grpc gateway reverse proxy.
	gatewayCreds := insecure.NewCredentials()
	if !s.config.insecure() {
		gatewayCreds = credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true, // #nosec
		})
	}
	gatewayOpts := grpc.WithTransportCredentials(gatewayCreds)
	conn, err := grpc.NewClient(
		s.config.gatewayAddress(), gatewayOpts,
	)
	if err != nil {
		return err
	}
	// Reverse proxy grpc-gateway.
	gwmux := runtime.NewServeMux(
		runtime.WithHealthzEndpoint(grpchealth.NewHealthClient(conn)),
		runtime.WithMarshalerOption("application/json+pretty", &runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				Indent:    "  ",
				Multiline: true,
			},
			UnmarshalOptions: protojson.UnmarshalOptions{
				DiscardUnknown: true,
			},
		}),
	)
	ctx := context.Background()
	if err := arkv1.RegisterAdminServiceHandler(
		ctx, gwmux, conn,
	); err != nil {
		return err
	}
	if err := arkv1.RegisterWalletServiceHandler(
		ctx, gwmux, conn,
	); err != nil {
		return err
	}
	if withAppSvc {
		if err := arkv1.RegisterArkServiceHandler(
			ctx, gwmux, conn,
		); err != nil {
			return err
		}
	}
	grpcGateway := http.Handler(gwmux)

	handler := router(grpcServer, grpcGateway)
	mux := http.NewServeMux()
	mux.Handle("/", handler)

	httpServerHandler := http.Handler(mux)
	if s.config.insecure() {
		httpServerHandler = h2c.NewHandler(httpServerHandler, &http2.Server{})
	}

	s.server = &http.Server{
		Addr:      s.config.address(),
		Handler:   httpServerHandler,
		TLSConfig: s.config.tlsConfig(),
	}

	return nil
}

func (s *service) onUnlock() {
	withoutAppSvc := false
	s.stop(withoutAppSvc)

	withAppSvc := true
	if err := s.start(withAppSvc); err != nil {
		panic(err)
	}
}

func router(
	grpcServer *grpc.Server, grpcGateway http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isOptionRequest(r) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			w.Header().Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			return
		}

		if isHttpRequest(r) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			w.Header().Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

			grpcGateway.ServeHTTP(w, r)
			return
		}
		grpcServer.ServeHTTP(w, r)
	})
}

func isOptionRequest(req *http.Request) bool {
	return req.Method == http.MethodOptions
}

func isHttpRequest(req *http.Request) bool {
	return req.Method == http.MethodGet ||
		strings.Contains(req.Header.Get("Content-Type"), "application/json")
}
