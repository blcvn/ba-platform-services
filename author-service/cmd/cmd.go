package cmd

import (
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "author-service",
	Short: "Authorization service for enterprise application",
	Long:  "Authorization service that manages Tenants, Roles, and Permissions",
}

var (
	serviceName string
	jaegerUrl   string
	metricsPath string
	grpcPort    int
	httpPort    int
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the author service server",
	Long:  "Start the author service with gRPC and HTTP gateway servers",
	Run: func(cmd *cobra.Command, args []string) {
		Gateway(serviceName, jaegerUrl, metricsPath, grpcPort, httpPort)
	},
}

func init() {
	serverCmd.Flags().StringVar(&serviceName, "service-name", "author-service", "Name of the service")
	serverCmd.Flags().StringVar(&jaegerUrl, "jaeger-url", "localhost:4317", "Jaeger OTLP endpoint URL")
	serverCmd.Flags().StringVar(&metricsPath, "metrics-path", "/metrics", "Path for Prometheus metrics endpoint")
	serverCmd.Flags().IntVar(&grpcPort, "grpc-port", 9091, "gRPC server port") // Different default port than auth-service (9090)
	serverCmd.Flags().IntVar(&httpPort, "http-port", 8081, "HTTP server port") // Different default port than auth-service (8080)

	RootCmd.AddCommand(serverCmd)
}
