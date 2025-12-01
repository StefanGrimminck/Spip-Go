package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

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

	// Determine runtime tuning with sensible defaults
	ratePerSec := float64(cfg.RateLimitPerSecond)
	if ratePerSec == 0 {
		ratePerSec = 20
	}
	burst := cfg.RateLimitBurst
	if burst == 0 {
		burst = 50000
	}
	readTimeout := time.Duration(cfg.ReadTimeoutSeconds) * time.Second
	if readTimeout == 0 {
		readTimeout = 30 * time.Second
	}
	writeTimeout := time.Duration(cfg.WriteTimeoutSeconds) * time.Second
	if writeTimeout == 0 {
		writeTimeout = 10 * time.Second
	}

	// Create network handler
	handler := network.NewHandler(logger, tlsHandler, ratePerSec, burst, readTimeout, writeTimeout)

	// Create TCP listener
	addr := fmt.Sprintf("%s:%d", cfg.IP, cfg.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("main", fmt.Sprintf("Failed to create listener: %v", err))
		os.Exit(1)
	}
	defer listener.Close()

	logger.Info("main", fmt.Sprintf("Listening on %s", addr))

	// Accept connections and handle graceful shutdown on signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	acceptErrCh := make(chan error, 1)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				// If listener was closed as part of shutdown, exit goroutine
				acceptErrCh <- err
				return
			}
			tcpConn := conn.(*net.TCPConn)
			go handler.HandleConnection(tcpConn)
		}
	}()

	// Wait for shutdown signal
	<-stop
	logger.Info("main", "Shutdown signal received, closing listener")
	listener.Close()

	// Give active connections up to 15s to finish, then force close
	if err := handler.Shutdown(15 * time.Second); err != nil {
		logger.Warn("main", fmt.Sprintf("Graceful shutdown completed with error: %v", err))
	} else {
		logger.Info("main", "Graceful shutdown completed")
	}
}
