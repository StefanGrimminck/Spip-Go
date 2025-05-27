package tls

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
)

// Config represents TLS configuration
type Config struct {
	CertPath           string
	KeyPath            string
	InsecureSkipVerify bool
}

// TLSHandler handles TLS connections
type TLSHandler struct {
	config *tls.Config
}

// NewTLSHandler creates a new TLS handler
func NewTLSHandler(cfg *Config) (*TLSHandler, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
	}

	return &TLSHandler{config: config}, nil
}

// IsTLSHandshake checks if the connection starts with a TLS handshake
func IsTLSHandshake(reader *bufio.Reader) bool {
	// TLS handshake starts with a record type of 0x16 (22)
	// followed by version (two bytes) and length (two bytes)
	firstByte, err := reader.Peek(1)
	if err != nil {
		return false
	}
	return len(firstByte) == 1 && firstByte[0] == 0x16
}

// WrapConnection wraps a TCP connection with TLS if it detects a TLS handshake
func (h *TLSHandler) WrapConnection(conn net.Conn) (net.Conn, bool, error) {
	// Create a buffered reader to peek at the first bytes
	reader := bufio.NewReader(conn)

	// Check if this is a TLS handshake
	if !IsTLSHandshake(reader) {
		// Not a TLS connection, return original connection
		return &readWriteConn{reader, conn}, false, nil
	}

	// It's a TLS connection, wrap it
	tlsConn := tls.Server(&readWriteConn{reader, conn}, h.config)
	if err := tlsConn.Handshake(); err != nil {
		return nil, true, fmt.Errorf("TLS handshake failed: %w", err)
	}
	return tlsConn, true, nil
}

// readWriteConn combines a buffered reader with a net.Conn
type readWriteConn struct {
	*bufio.Reader
	net.Conn
}

func (rwc *readWriteConn) Read(p []byte) (n int, err error) {
	return rwc.Reader.Read(p)
}

// Stream represents either a TLS or plain TCP connection
type Stream struct {
	conn  io.ReadWriteCloser
	isTLS bool
}

// NewTLSStream creates a new TLS stream
func NewTLSStream(conn net.Conn) *Stream {
	return &Stream{
		conn:  conn,
		isTLS: true,
	}
}

// NewPlainStream creates a new plain TCP stream
func NewPlainStream(conn net.Conn) *Stream {
	return &Stream{
		conn:  conn,
		isTLS: false,
	}
}

// Read implements io.Reader
func (s *Stream) Read(p []byte) (n int, err error) {
	return s.conn.Read(p)
}

// Write implements io.Writer
func (s *Stream) Write(p []byte) (n int, err error) {
	return s.conn.Write(p)
}

// Close implements io.Closer
func (s *Stream) Close() error {
	return s.conn.Close()
}

// IsTLS returns whether this is a TLS connection
func (s *Stream) IsTLS() bool {
	return s.isTLS
}
