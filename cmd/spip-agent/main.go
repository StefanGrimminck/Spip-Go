package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"spip/internal/config"
	"spip/internal/logging"
	"spip/internal/network"
	"spip/internal/tls"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config.toml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid configuration: %v\n", err)
		os.Exit(1)
	}

	// Create logger
	var logger logging.Logger
	if cfg.LogFile != "" {
		logFile, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
			os.Exit(1)
		}
		defer logFile.Close()
		logger = logging.NewLogger(logFile)
	} else {
		logger = logging.NewLogger(os.Stdout)
	}

	logger.Info("main", "Starting Spip agent...")

	// Initialize TLS if configured
	var tlsHandler *tls.TLSHandler
	if cfg.IsTLSEnabled() {
		tlsHandler, err = tls.NewTLSHandler(&tls.Config{
			CertPath: cfg.CertPath,
			KeyPath:  cfg.KeyPath,
		})
		if err != nil {
			logger.Error("main", fmt.Sprintf("Failed to initialize TLS: %v", err))
			os.Exit(1)
		}
		logger.Info("main", "TLS enabled")
	} else {
		logger.Info("main", "Running in plain TCP mode")
	}

	// Create network handler
	handler := network.NewHandler(logger, tlsHandler)

	// Create TCP listener
	addr := fmt.Sprintf("%s:%d", cfg.IP, cfg.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("main", fmt.Sprintf("Failed to create listener: %v", err))
		os.Exit(1)
	}
	defer listener.Close()

	logger.Info("main", fmt.Sprintf("Listening on %s", addr))

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("main", fmt.Sprintf("Failed to accept connection: %v", err))
			continue
		}

		// Handle connection in a goroutine
		tcpConn := conn.(*net.TCPConn)
		go handler.HandleConnection(tcpConn)
	}
}
