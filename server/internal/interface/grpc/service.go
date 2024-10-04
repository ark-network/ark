package grpcservice

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	appconfig "github.com/ark-network/ark/server/internal/app-config"
	"github.com/ark-network/ark/server/internal/core/application"
	interfaces "github.com/ark-network/ark/server/internal/interface"
	"github.com/ark-network/ark/server/internal/interface/grpc/handlers"
	"github.com/ark-network/ark/server/internal/interface/grpc/interceptors"
	"github.com/ark-network/ark/server/pkg/kvdb"
	"github.com/ark-network/ark/server/pkg/macaroons"
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

const (
	macaroonsLocation = "ark"
	macaroonsDbFile   = "macaroons.db"
	macaroonsFolder   = "macaroons"

	tlsKeyFile  = "key.pem"
	tlsCertFile = "cert.pem"
	tlsFolder   = "tls"
)

type service struct {
	config      Config
	appConfig   *appconfig.Config
	server      *http.Server
	grpcServer  *grpc.Server
	macaroonSvc *macaroons.Service
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

	var macaroonSvc *macaroons.Service
	if !svcConfig.NoMacaroons {
		macaroonDB, err := kvdb.Create(
			kvdb.BoltBackendName,
			filepath.Join(svcConfig.Datadir, macaroonsDbFile),
			true,
			kvdb.DefaultDBTimeout,
		)
		if err != nil {
			return nil, err
		}

		keyStore, err := macaroons.NewRootKeyStorage(macaroonDB)
		if err != nil {
			return nil, err
		}
		svc, err := macaroons.NewService(
			keyStore, macaroonsLocation, false, macaroons.IPLockChecker,
		)
		if err != nil {
			return nil, err
		}
		macaroonSvc = svc
	}

	if !svcConfig.insecure() {
		if err := generateOperatorTLSKeyCert(
			svcConfig.tlsDatadir(), svcConfig.TLSExtraIPs, svcConfig.TLSExtraDomains,
		); err != nil {
			return nil, err
		}
		log.Debugf("generated TLS key pair at path: %s", svcConfig.tlsDatadir())
	}

	return &service{svcConfig, appConfig, nil, nil, macaroonSvc}, nil
}

func (s *service) Start() error {
	withoutAppSvc := false
	if err := s.start(withoutAppSvc); err != nil {
		return err
	}
	if s.appConfig.UnlockerService() != nil {
		return s.autoUnlock()
	}
	return nil
}

func (s *service) Stop() {
	withAppSvc := true
	s.stop(withAppSvc)
}

func (s *service) start(withAppSvc bool) error {
	tlsConfig, err := s.config.tlsConfig()
	if err != nil {
		return err
	}

	if err := s.newServer(tlsConfig, withAppSvc); err != nil {
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

func (s *service) newServer(tlsConfig *tls.Config, withAppSvc bool) error {
	grpcConfig := []grpc.ServerOption{
		interceptors.UnaryInterceptor(s.macaroonSvc),
		interceptors.StreamInterceptor(s.macaroonSvc),
	}
	creds := insecure.NewCredentials()
	if !s.config.insecure() {
		creds = credentials.NewTLS(tlsConfig)
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

	walletHandler := handlers.NewWalletHandler(s.appConfig.WalletService())
	arkv1.RegisterWalletServiceServer(grpcServer, walletHandler)

	walletInitHandler := handlers.NewWalletInitializerHandler(
		s.appConfig.WalletService(), s.onInit, s.onUnlock,
	)
	arkv1.RegisterWalletInitializerServiceServer(grpcServer, walletInitHandler)

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

	customMatcher := func(key string) (string, bool) {
		switch key {
		case "X-Macaroon":
			return "macaroon", true
		default:
			return key, false
		}
	}
	// Reverse proxy grpc-gateway.
	gwmux := runtime.NewServeMux(
		runtime.WithIncomingHeaderMatcher(customMatcher),
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
	if err := arkv1.RegisterWalletInitializerServiceHandler(
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
		TLSConfig: tlsConfig,
	}

	return nil
}

func (s *service) onUnlock(password string) {
	withoutAppSvc := false
	s.stop(withoutAppSvc)

	withAppSvc := true
	if err := s.start(withAppSvc); err != nil {
		panic(err)
	}

	if s.config.NoMacaroons {
		return
	}

	pwd := []byte(password)
	datadir := s.config.macaroonsDatadir()
	if err := s.macaroonSvc.CreateUnlock(&pwd); err != nil {
		if err != macaroons.ErrAlreadyUnlocked {
			log.WithError(err).Warn("failed to unlock macaroon store")
		}
	}

	done, err := genMacaroons(
		context.Background(), s.macaroonSvc, datadir,
	)
	if err != nil {
		log.WithError(err).Warn("failed to create macaroons")
	}
	if done {
		log.Debugf("created and stored macaroons at path %s", datadir)
	}
}

func (s *service) onInit(password string) {
	if s.config.NoMacaroons {
		return
	}

	pwd := []byte(password)
	datadir := s.config.macaroonsDatadir()
	if err := s.macaroonSvc.CreateUnlock(&pwd); err != nil {
		log.WithError(err).Warn("failed to initialize macaroon store")
	}
	if _, err := genMacaroons(
		context.Background(), s.macaroonSvc, datadir,
	); err != nil {
		log.WithError(err).Warn("failed to create macaroons")
	}
	log.Debugf("generated macaroons at path %s", datadir)
}

func (s *service) autoUnlock() error {
	ctx := context.Background()
	wallet := s.appConfig.WalletService()
	unlocker := s.appConfig.UnlockerService()

	password, err := unlocker.GetPassword(ctx)
	if err != nil {
		return fmt.Errorf("failed to get password: %s", err)
	}
	if err := wallet.Unlock(ctx, password); err != nil {
		return fmt.Errorf("failed to auto unlock: %s", err)
	}

	go s.onUnlock(password)

	log.Debug("service auto unlocked")
	return nil
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
