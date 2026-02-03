package cmd

import (
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "session-service",
	Short: "Session service for BA Agent",
	Long:  "Session service with gRPC and HTTP gateway support",
}

var (
	serviceName string
	jaegerUrl   string
	metricsPath string
	grpcPort    int
	httpPort    int
)

var gatewayCmd = &cobra.Command{
	Use:   "gateway",
	Short: "Start the session service gateway",
	Long:  "Start the session service with gRPC and HTTP gateway servers",
	Run: func(cmd *cobra.Command, args []string) {
		Gateway(serviceName, jaegerUrl, metricsPath, grpcPort, httpPort)
	},
}

func init() {
	gatewayCmd.Flags().StringVar(&serviceName, "session-service", "session-service", "Name of the service")
	gatewayCmd.Flags().StringVar(&jaegerUrl, "jaeger-url", "localhost:4317", "Jaeger OTLP endpoint URL")
	gatewayCmd.Flags().StringVar(&metricsPath, "metrics-path", "/metrics", "Path for Prometheus metrics endpoint")
	gatewayCmd.Flags().IntVar(&grpcPort, "grpc-port", 9090, "gRPC server port")
	gatewayCmd.Flags().IntVar(&httpPort, "http-port", 8080, "HTTP server port")

	RootCmd.AddCommand(gatewayCmd)
}
