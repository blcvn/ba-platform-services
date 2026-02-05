package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strings"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/logging"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/middleware/tracing"
	"github.com/go-kratos/kratos/v2/transport"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	"github.com/go-kratos/kratos/v2/transport/http"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/blcvn/backend/services/pkg/mtls"
	"github.com/blcvn/backend/services/session-service/common/configs"
	"github.com/blcvn/backend/services/session-service/controllers"
	"github.com/blcvn/backend/services/session-service/helper"
	postgres "github.com/blcvn/backend/services/session-service/repository/postgres"
	"github.com/blcvn/backend/services/session-service/usecases"
	pb "github.com/blcvn/kratos-proto/go/session"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// controllerDeps holds all controller dependencies
type controllerDeps struct {
	sessionCtrl pb.SessionServiceServer
}

// setTracerProvider configures an OTLP exporter, and configures the corresponding trace provider.
func setTracerProvider(ctx context.Context, endpoint string) (func(context.Context) error, error) {
	exporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithEndpoint(endpoint), otlptracegrpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("session-service"),
		)),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	fmt.Printf("Tracer & Propagator initialized with endpoint: %s\n", endpoint)
	return tp.Shutdown, nil
}

// setupDatabase initializes database connection
func setupDatabase(appLog *log.Helper, cfg *configs.Config) *gorm.DB {
	dsn := cfg.Database.URL
	if dsn == "" {
		appLog.Fatal("database URL is empty")
	}

	db, err := gorm.Open(pgdriver.Open(dsn), &gorm.Config{})
	if err != nil {
		appLog.Fatalf("failed to connect to database: %v", err)
	}

	appLog.Info("database connection established")
	return db
}

// setupUsecasesAndControllers wires up usecases and controllers
func setupUsecasesAndControllers(appLog *log.Helper, cfg *configs.Config) *controllerDeps {
	// 1. setup database
	db := setupDatabase(appLog, cfg)

	// 2. setupRepositories initializes all repositories
	repo := postgres.NewSessionRepository(db)

	// 3. Initialize usecases
	uc := usecases.NewSessionUsecase(repo)

	// 4. Initialize helpers
	transform := helper.NewTransform()

	// 5. Initialize controllers
	controller := controllers.NewSessionController(uc, transform)

	return &controllerDeps{
		sessionCtrl: controller,
	}
}

// setupGRPCServer creates and configures gRPC server
func setupGRPCServer(
	logger log.Logger,
	grpcPort int,
	reloader *mtls.CertReloader,
	ctrls *controllerDeps,
) transport.Server {
	grpcOpts := []grpc.ServerOption{
		grpc.Middleware(
			recovery.Recovery(),
			tracing.Server(),
			logging.Server(logger),
		),
		grpc.Address(fmt.Sprintf(":%d", grpcPort)),
	}

	if reloader != nil {
		grpcOpts = append(grpcOpts, grpc.TLSConfig(&tls.Config{
			GetConfigForClient: reloader.GetConfigForClient,
		}))
	}

	grpcSrv := grpc.NewServer(grpcOpts...)

	// Register gRPC services
	pb.RegisterSessionServiceServer(grpcSrv, ctrls.sessionCtrl)

	return grpcSrv
}

// setupHTTPServer creates and configures HTTP server with grpc-gateway
func setupHTTPServer(
	ctx context.Context,
	logger log.Logger,
	appLog *log.Helper,
	httpPort int,
	metricsPath string,
	reloader *mtls.CertReloader,
	ctrls *controllerDeps,
) transport.Server {
	httpOpts := []http.ServerOption{
		http.Middleware(
			recovery.Recovery(),
			tracing.Server(),
			logging.Server(logger),
		),
		http.Address(fmt.Sprintf(":%d", httpPort)),
	}

	if reloader != nil {
		httpOpts = append(httpOpts, http.TLSConfig(&tls.Config{
			GetConfigForClient: reloader.GetConfigForClient,
		}))
	}

	httpSrv := http.NewServer(httpOpts...)

	// Create grpc-gateway mux
	gwmux := runtime.NewServeMux(
		runtime.WithIncomingHeaderMatcher(customMatcher),
	)

	// Register grpc-gateway handlers
	if err := pb.RegisterSessionServiceHandlerServer(ctx, gwmux, ctrls.sessionCtrl); err != nil {
		appLog.Fatalf("failed to register session gateway: %v", err)
	}

	// Add Prometheus metrics endpoint
	httpSrv.Route("/").GET(metricsPath, func(ctx http.Context) error {
		promhttp.Handler().ServeHTTP(ctx.Response(), ctx.Request())
		return nil
	})

	// Mount grpc-gateway on HTTP server
	httpSrv.HandlePrefix("/", gwmux)

	return httpSrv
}

// customMatcher allows specific headers to pass through grpc-gateway
func customMatcher(key string) (string, bool) {
	switch strings.ToLower(key) {
	case "x-user-id", "x-tenant-id", "x-roles", "tenant_id", "tenant-id":
		return key, true
	default:
		return runtime.DefaultHeaderMatcher(key)
	}
}

// Gateway initializes and runs the session service gateway
func Gateway(serviceName, jaegerUrl, metricsPath string, grpcPort, httpPort int) {
	ctx := context.Background()
	// 1. Setup logger
	logger := log.With(log.NewStdLogger(os.Stdout),
		"ts", log.DefaultTimestamp,
		"caller", log.DefaultCaller,
		"service.name", serviceName,
	)
	appLog := log.NewHelper(logger)

	// 2. Initialize configs
	cfg, err := configs.LoadConfig()
	if err != nil {
		appLog.Fatalf("failed to load configs: %v", err)
	}

	// 3. Initialize tracing
	traceShutdown, err := setTracerProvider(ctx, jaegerUrl)
	if err != nil {
		fmt.Printf("failed to init tracer: %v\n", err)
	} else {
		defer traceShutdown(ctx)
		// Test span
		tr := otel.Tracer(serviceName)
		_, span := tr.Start(ctx, fmt.Sprintf("%s-startup", serviceName))
		span.End()
		fmt.Println("Sent test span to Jaeger")
	}

	// 4. Setup infrastructure
	ctrls := setupUsecasesAndControllers(appLog, cfg)

	// 5. Setup mTLS
	tlsCertPath := "/vault/secrets/tls.crt"
	tlsKeyPath := "/vault/secrets/tls.key"

	reloader, err := mtls.NewCertReloader(tlsCertPath, tlsKeyPath)
	if err != nil {
		appLog.Warnf("failed to load mTLS certificates: %v", err)
	}

	// 6. Setup servers
	services := []transport.Server{}

	if grpcPort > 0 {
		grpcSrv := setupGRPCServer(logger, grpcPort, reloader, ctrls)
		services = append(services, grpcSrv)
	}

	if httpPort > 0 {
		httpSrv := setupHTTPServer(ctx, logger, appLog, httpPort, metricsPath, reloader, ctrls)
		services = append(services, httpSrv)
	}

	if len(services) == 0 {
		appLog.Fatal("no server configured")
	}

	// Create and run Kratos application
	app := kratos.New(
		kratos.Name(serviceName),
		kratos.Logger(logger),
		kratos.Server(services...),
	)

	appLog.Infof("Starting %s with gRPC on :%d and HTTP on :%d", serviceName, grpcPort, httpPort)
	if err := app.Run(); err != nil {
		appLog.Fatal(err)
	}
}
