package network

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"spip/internal/logging"
	"spip/internal/tls"
	"spip/pkg/socket"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// Handler handles network connections
type Handler struct {
	logger      logging.Logger
	tlsHandler  *tls.TLSHandler
	limiter     *rate.Limiter
	connections sync.Map
	// Add configuration for timeouts
	readTimeout  time.Duration
	writeTimeout time.Duration
}

// NewHandler creates a new network handler
func NewHandler(logger logging.Logger, tlsHandler *tls.TLSHandler) *Handler {
	// Allow bursts of up to 50000 connections, with 20 tokens per second
	// This allows for handling large spikes while preventing resource exhaustion
	// 20 tokens/sec = 1.73 million requests per day (well above 1M target)
	// Large burst size (50000) to handle probe spikes
	return &Handler{
		logger:       logger,
		tlsHandler:   tlsHandler,
		limiter:      rate.NewLimiter(20, 50000),
		readTimeout:  30 * time.Second, // Increased from 10s
		writeTimeout: 10 * time.Second, // New write timeout
	}
}

// isHTTPRequest checks if the data looks like an HTTP request
func isHTTPRequest(data []byte) bool {
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
	for _, method := range methods {
		if bytes.HasPrefix(data, []byte(method+" ")) {
			return true
		}
	}
	return false
}

// handleHTTPRequest handles an HTTP request and returns an HTTP response
func handleHTTPRequest(data []byte) []byte {
	content := "Hello from Spip!"
	return []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(content), content))
}

// isConnectionClosed checks if an error indicates a closed connection
func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout() || netErr.Temporary()
	}
	// Common scanner behavior: connection reset or broken pipe
	if err.Error() == "read: connection reset by peer" ||
		err.Error() == "write: broken pipe" {
		return true
	}
	return false
}

// shouldLogError determines if an error should be logged
func shouldLogError(err error) bool {
	if err == nil {
		return false
	}

	// Only log errors that are not connection-related
	if strings.Contains(err.Error(), "tls:") ||
		strings.Contains(err.Error(), "read:") ||
		strings.Contains(err.Error(), "write:") ||
		strings.Contains(err.Error(), "i/o timeout") ||
		err == io.EOF ||
		isConnectionClosed(err) {
		return false
	}

	// Log only truly unexpected errors
	return true
}

// classifyConnectionError categorizes connection errors for appropriate logging
func classifyConnectionError(err error) (severity string, isExpected bool) {
	if err == nil {
		return "", true
	}

	// Common scanner behaviors - debug level
	if err == io.EOF ||
		err.Error() == "read: connection reset by peer" ||
		err.Error() == "write: broken pipe" ||
		strings.Contains(err.Error(), "i/o timeout") {
		return "debug", true
	}

	// Expected TLS probing behaviors - info level
	if strings.Contains(err.Error(), "tls: first record does not look like a TLS handshake") ||
		strings.Contains(err.Error(), "tls: bad certificate") ||
		strings.Contains(err.Error(), "tls: handshake failure") ||
		strings.Contains(err.Error(), "tls: client offered only unsupported versions") ||
		strings.Contains(err.Error(), "tls: no cipher suite supported") {
		return "info", true
	}

	// Network timeouts and temporary errors - debug level
	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() || netErr.Temporary() {
			return "debug", true
		}
	}

	// Anything else might be worth investigating
	return "error", false
}

// HandleConnection handles an incoming TCP connection
func (h *Handler) HandleConnection(conn *net.TCPConn) {
	// Set TCP keep-alive to detect dead connections
	conn.SetKeepAlive(true)
	conn.SetKeepAlivePeriod(60 * time.Second)

	// Apply rate limiting
	if !h.limiter.Allow() {
		h.logger.Error("network", "Connection rejected due to rate limiting")
		conn.Close()
		return
	}

	// Store connection in the active connections map
	connID := uuid.New().String()
	h.connections.Store(connID, conn)

	// Create a channel to signal connection completion
	done := make(chan struct{})

	// Handle connection cleanup in a deferred function
	defer func() {
		close(done)
		h.connections.Delete(connID)
		conn.Close()
	}()

	// Get original destination
	origDst, err := socket.GetOriginalDst(conn)
	if err != nil {
		return
	}

	// Get connection info
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)

	var stream *tls.Stream
	if h.tlsHandler != nil {
		// Try to detect and handle TLS
		wrappedConn, isTLS, err := h.tlsHandler.WrapConnection(conn)
		if err != nil {
			if isTLS {
				return // Silently fail TLS handshake
			}
			// Not a TLS connection, continue with plain TCP
			stream = tls.NewPlainStream(conn)
		} else {
			// Successfully wrapped as TLS or plain TCP
			if isTLS {
				stream = tls.NewTLSStream(wrappedConn)
			} else {
				stream = tls.NewPlainStream(wrappedConn)
			}
		}
	} else {
		stream = tls.NewPlainStream(conn)
	}
	defer stream.Close()

	sessionID := uuid.New().String()
	buffer := make([]byte, 16384)

	for {
		select {
		case <-done:
			return
		default:
			// Set read deadline
			conn.SetReadDeadline(time.Now().Add(h.readTimeout))

			n, err := stream.Read(buffer)
			if err != nil {
				return
			}

			if n == 0 {
				return // Connection closed
			}

			// Check if this is an HTTP request
			var response []byte
			if isHTTPRequest(buffer[:n]) {
				response = handleHTTPRequest(buffer[:n])
			} else {
				response = buffer[:n] // Echo back for non-HTTP requests
			}

			// Set write deadline
			conn.SetWriteDeadline(time.Now().Add(h.writeTimeout))

			// Write response
			if _, err := stream.Write(response); err != nil {
				return
			}

			// Log connection data
			connData := &logging.ConnectionData{
				Timestamp:       time.Now().Unix(),
				Payload:         string(buffer[:n]),
				PayloadHex:      hex.EncodeToString(buffer[:n]),
				SourceIP:        remoteAddr.IP.String(),
				SourcePort:      uint16(remoteAddr.Port),
				DestinationIP:   origDst.IP.String(),
				DestinationPort: origDst.Port,
				SessionID:       sessionID,
				IsTLS:           stream.IsTLS(),
			}

			if err := h.logger.LogConnection(connData); err != nil {
				h.logger.Error("network", fmt.Sprintf("Failed to log connection data: %v", err))
			}
		}
	}
}
