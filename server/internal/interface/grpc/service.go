package grpcservice

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"path/filepath"
	"runtime/metrics"
	"sort"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	metricExport "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	traceExport "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/server/internal/config"
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
	version      string
	config       Config
	appConfig    *config.Config
	server       *http.Server
	grpcServer   *grpc.Server
	macaroonSvc  *macaroons.Service
	otelShutdown func(context.Context) error

	stopCh chan (struct{})
}

func NewService(
	version string, svcConfig Config, appConfig *config.Config,
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

	stopCh := make(chan struct{}, 1)

	return &service{version, svcConfig, appConfig, nil, nil, macaroonSvc, nil, stopCh}, nil
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
	if s.otelShutdown != nil {
		if err := s.otelShutdown(context.Background()); err != nil {
			log.Errorf("failed to shutdown otel: %s", err)
		}
	}
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
		s.stopCh <- struct{}{}
		appSvc, _ := s.appConfig.AppService()
		if appSvc != nil {
			appSvc.Stop()
			log.Info("stopped app service")
		}
	}
}

func (s *service) newServer(tlsConfig *tls.Config, withAppSvc bool) error {
	if s.appConfig.OtelCollectorEndpoint != "" {
		otelShutdown, err := initOpenTelemetry(context.Background(), s.appConfig.OtelCollectorEndpoint)
		if err != nil {
			return err
		}

		s.otelShutdown = otelShutdown
	}

	otelHandler := otelgrpc.NewServerHandler(
		otelgrpc.WithTracerProvider(otel.GetTracerProvider()),
	)

	grpcConfig := []grpc.ServerOption{
		interceptors.UnaryInterceptor(s.macaroonSvc),
		interceptors.StreamInterceptor(s.macaroonSvc),
		grpc.StatsHandler(otelHandler),
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
		appHandler := handlers.NewHandler(s.version, appSvc, s.stopCh)
		arkv1.RegisterArkServiceServer(grpcServer, appHandler)
		arkv1.RegisterExplorerServiceServer(grpcServer, appHandler)
	}

	adminHandler := handlers.NewAdminHandler(s.appConfig.AdminService(), appSvc, s.appConfig.NoteUriPrefix)
	arkv1.RegisterAdminServiceServer(grpcServer, adminHandler)

	walletHandler := handlers.NewWalletHandler(s.appConfig.WalletService())
	arkv1.RegisterWalletServiceServer(grpcServer, walletHandler)

	walletInitHandler := handlers.NewWalletInitializerHandler(
		s.appConfig.WalletService(), s.onInit, s.onUnlock, s.onReady,
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
		if err := arkv1.RegisterExplorerServiceHandler(
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

func (s *service) onReady() {
	withoutAppSvc := false
	s.stop(withoutAppSvc)

	withAppSvc := true
	if err := s.start(withAppSvc); err != nil {
		panic(err)
	}
}

func (s *service) autoUnlock() error {
	ctx := context.Background()
	wallet := s.appConfig.WalletService()

	status, err := wallet.Status(ctx)
	if err != nil {
		return fmt.Errorf("failed to get wallet status: %s", err)
	}
	if !status.IsInitialized() {
		log.Debug("wallet not initiialized, skipping auto unlock")
		return nil
	}

	password, err := s.appConfig.UnlockerService().GetPassword(ctx)
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

func initOpenTelemetry(ctx context.Context, otelCollectorUrl string) (func(context.Context) error, error) {
	// Remove trailing slash if present
	otelCollectorUrl = strings.TrimSuffix(otelCollectorUrl, "/")

	traceExp, err := traceExport.New(
		ctx,
		traceExport.WithEndpoint(strings.TrimPrefix(otelCollectorUrl, "http://")), //TODO double check
		traceExport.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create trace exporter: %w", err)
	}

	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName("arkd"),
	)
	tp := trace.NewTracerProvider(
		trace.WithBatcher(traceExp),
		trace.WithResource(res),
	)

	metricExp, err := metricExport.New(
		ctx,
		metricExport.WithEndpoint(strings.TrimPrefix(otelCollectorUrl, "http://")), // Remove http:// prefix
		metricExport.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create metric exporter: %w", err)
	}

	reader := sdkmetric.NewPeriodicReader(
		metricExp,
		sdkmetric.WithInterval(5*time.Second),
	)

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
		sdkmetric.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)

	// Start collecting runtime metrics
	go collectRuntimeMetrics(ctx)

	log.Info("initialized opentelemetry")

	shutdown := func(ctx context.Context) error {
		err1 := tp.Shutdown(ctx)
		err2 := mp.Shutdown(ctx)
		if err1 != nil {
			return err1
		}
		return err2
	}
	return shutdown, nil
}

func collectRuntimeMetrics(ctx context.Context) {
	meter := otel.Meter("runtime.metrics")

	// Define our metrics by their semantic type
	gaugeMetrics := map[string]bool{
		// Memory metrics (gauges)
		"/memory/classes/heap/objects:bytes":  true,
		"/memory/classes/heap/free:bytes":     true,
		"/memory/classes/heap/released:bytes": true,
		"/memory/classes/heap/stacks:bytes":   true,
		"/memory/classes/total:bytes":         true,

		// GC gauges
		"/gc/heap/objects:objects": true,
		"/gc/heap/goal:bytes":      true,

		// Scheduler gauges
		"/sched/goroutines:goroutines": true,
		"/sched/gomaxprocs:threads":    true,

		// Histogram metrics (will extract gauge-like statistics)
		"/gc/pauses:seconds": true,
	}

	metrics.All()

	counterMetrics := map[string]bool{
		// Counters (monotonically increasing)
		"/gc/cycles/total:gc-cycles":     true,
		"/sync/mutex/wait/total:seconds": true,
	}

	// Combine all metrics for tracking
	allMetrics := make(map[string]bool)
	for k, v := range gaugeMetrics {
		allMetrics[k] = v
	}
	for k, v := range counterMetrics {
		allMetrics[k] = v
	}

	// Create sample slice
	var samples []metrics.Sample
	for name := range allMetrics {
		samples = append(samples, metrics.Sample{Name: name})
	}

	// Helper function to format the metric name for OpenTelemetry
	formatMetricName := func(rawName string) string {
		// Replace slashes and colons with underscores
		name := strings.ReplaceAll(rawName, "/", "_")
		name = strings.ReplaceAll(name, ":", "_")
		// Add the ark_ prefix
		return "ark" + name
	}

	// Register all metrics with their individual names
	_, err := meter.Int64ObservableGauge(
		"ark_runtime_metrics_gauge",
		metric.WithDescription("Ark runtime gauge metrics"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			// Read all metric values
			metrics.Read(samples)

			// Process all samples
			for _, sample := range samples {
				if sample.Value.Kind() == metrics.KindBad {
					continue
				}

				// Format the metric name
				metricName := formatMetricName(sample.Name)

				// Handle gauge metrics
				if gaugeMetrics[sample.Name] {
					switch sample.Value.Kind() {
					case metrics.KindUint64:
						o.Observe(int64(sample.Value.Uint64()), metric.WithAttributes(
							attribute.String("metric_name", metricName),
						))
					case metrics.KindFloat64:
						o.Observe(int64(sample.Value.Float64()), metric.WithAttributes(
							attribute.String("metric_name", metricName),
						))
					case metrics.KindFloat64Histogram:
						// For histograms, extract statistics
						hist := sample.Value.Float64Histogram()
						if len(hist.Counts) > 0 {
							// Calculate mean
							var sum, count float64
							for i, c := range hist.Counts {
								if i+1 < len(hist.Buckets) {
									midpoint := (hist.Buckets[i] + hist.Buckets[i+1]) / 2
									sum += midpoint * float64(c)
									count += float64(c)
								}
							}

							if count > 0 {
								// Report mean
								o.Observe(int64(sum/count*1e9), metric.WithAttributes( // Convert to nanoseconds
									attribute.String("metric_name", metricName+"_mean"),
									attribute.String("statistic", "mean"),
								))

								// For GC pauses, also report p50, p90, p99 if we have enough data
								if count >= 10 && sample.Name == "/gc/pauses:seconds" {
									// This is a simplified percentile calculation
									var values []float64
									for i, c := range hist.Counts {
										if i+1 < len(hist.Buckets) {
											midpoint := (hist.Buckets[i] + hist.Buckets[i+1]) / 2
											for j := 0; j < int(c); j++ {
												values = append(values, midpoint)
											}
										}
									}

									// Sort for percentile calculation
									sort.Float64s(values)

									// Calculate percentiles
									if len(values) > 0 {
										p50idx := int(float64(len(values)) * 0.5)
										p90idx := int(float64(len(values)) * 0.9)
										p99idx := int(float64(len(values)) * 0.99)

										if p50idx < len(values) {
											o.Observe(int64(values[p50idx]*1e9), metric.WithAttributes(
												attribute.String("metric_name", metricName+"_p50"),
												attribute.String("statistic", "p50"),
											))
										}

										if p90idx < len(values) {
											o.Observe(int64(values[p90idx]*1e9), metric.WithAttributes(
												attribute.String("metric_name", metricName+"_p90"),
												attribute.String("statistic", "p90"),
											))
										}

										if p99idx < len(values) {
											o.Observe(int64(values[p99idx]*1e9), metric.WithAttributes(
												attribute.String("metric_name", metricName+"_p99"),
												attribute.String("statistic", "p99"),
											))
										}
									}
								}
							}
						}
					}
				}
			}

			return nil
		}),
	)

	if err != nil {
		log.Error(fmt.Sprintf("failed to register gauge metrics: %v", err))
		return
	}

	// Register counter metrics
	_, err = meter.Int64ObservableCounter(
		"ark_runtime_metrics_counter",
		metric.WithDescription("Ark runtime counter metrics"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			// Read all metrics again
			metrics.Read(samples)

			// Process counter metrics
			for _, sample := range samples {
				if !counterMetrics[sample.Name] || sample.Value.Kind() == metrics.KindBad {
					continue
				}

				// Format the metric name
				metricName := formatMetricName(sample.Name)

				switch sample.Value.Kind() {
				case metrics.KindUint64:
					o.Observe(int64(sample.Value.Uint64()), metric.WithAttributes(
						attribute.String("metric_name", metricName),
					))
				case metrics.KindFloat64:
					o.Observe(int64(sample.Value.Float64()), metric.WithAttributes(
						attribute.String("metric_name", metricName),
					))
				}
			}

			return nil
		}),
	)

	if err != nil {
		log.Error(fmt.Sprintf("failed to register counter metrics: %v", err))
	}

	log.Info("Started collecting Ark Go runtime metrics with metric_name attribute")
}
