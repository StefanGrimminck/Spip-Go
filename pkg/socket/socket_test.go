package socket

import (
	"net"
	"testing"
)

func TestGetOriginalDst(t *testing.T) {
	// Create a TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Get the listener's address
	listenerAddr := listener.Addr().(*net.TCPAddr)

	// Create a connection to the listener
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Accept the connection
	server, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to accept connection: %v", err)
	}
	defer server.Close()

	// Get original destination
	tcpConn := server.(*net.TCPConn)
	origDst, err := GetOriginalDst(tcpConn)
	if err != nil {
		t.Fatalf("GetOriginalDst failed: %v", err)
	}

	// In a non-redirected connection, original destination should match the listener's address
	if !origDst.IP.Equal(listenerAddr.IP) {
		t.Errorf("Expected IP %v, got %v", listenerAddr.IP, origDst.IP)
	}
	if origDst.Port != uint16(listenerAddr.Port) {
		t.Errorf("Expected port %d, got %d", listenerAddr.Port, origDst.Port)
	}
}

func TestGetOriginalDstInvalidConnection(t *testing.T) {
	// Create and immediately close a connection to test with an invalid file descriptor
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	server, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to accept connection: %v", err)
	}

	// Close the connection before trying to get original destination
	server.Close()
	client.Close()

	// Attempt to get original destination from closed connection
	tcpConn := server.(*net.TCPConn)
	_, err = GetOriginalDst(tcpConn)
	if err == nil {
		t.Error("Expected error when getting original destination from closed connection")
	}
}
