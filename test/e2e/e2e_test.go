package e2e

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testPort = 8080
	testHost = "127.0.0.1"
)

// testEnv represents a test environment
type testEnv struct {
	t           *testing.T
	configPath  string
	certPath    string
	keyPath     string
	spipProcess *os.Process
	stdout      *bytes.Buffer
	stdoutPipe  io.ReadCloser
	stdoutDone  chan struct{}
}

func startSpip(t *testing.T, configPath string) (*os.Process, *bytes.Buffer, io.ReadCloser) {
	// Get the path to the agent binary relative to the test directory
	agentPath := filepath.Join("..", "..", "spip-agent")
	cmd := exec.Command(agentPath, "-config", configPath)

	// Create a pipe for stdout
	stdout := &bytes.Buffer{}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to create stdout pipe: %v", err)
	}

	// Set up command output
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start spip-agent: %v", err)
	}

	// Start copying stdout in a goroutine
	go func() {
		io.Copy(io.MultiWriter(stdout, os.Stdout), stdoutPipe)
	}()

	// Wait for the server to start
	time.Sleep(time.Second)

	return cmd.Process, stdout, stdoutPipe
}

func setupTestEnv(t *testing.T, useTLS bool) *testEnv {
	// Build the agent first
	cmd := exec.Command("go", "build", "-o", filepath.Join("..", "..", "spip-agent"), filepath.Join("..", "..", "cmd", "spip-agent"))
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build spip-agent: %v", err)
	}

	if err := setupIptables(t); err != nil {
		t.Fatalf("Failed to setup iptables: %v", err)
	}

	var certPath, keyPath string
	if useTLS {
		certPath, keyPath = generateTestCertificate(t)
	}

	configPath := createTestConfig(t, useTLS, certPath, keyPath)
	process, stdout, stdoutPipe := startSpip(t, configPath)

	return &testEnv{
		t:           t,
		configPath:  configPath,
		certPath:    certPath,
		keyPath:     keyPath,
		spipProcess: process,
		stdout:      stdout,
		stdoutPipe:  stdoutPipe,
		stdoutDone:  make(chan struct{}),
	}
}

func (e *testEnv) cleanup() {
	if e.spipProcess != nil {
		stopSpip(e.t, e.spipProcess)
	}
	if e.configPath != "" {
		os.RemoveAll(filepath.Dir(e.configPath))
	}
	if e.certPath != "" {
		os.RemoveAll(filepath.Dir(e.certPath))
	}
	if e.stdoutPipe != nil {
		e.stdoutPipe.Close()
	}
	cleanupIptables(e.t)
}

// getStdout returns the current stdout buffer contents
func (e *testEnv) getStdout() string {
	// Wait for the pipe to close
	e.stdoutPipe.Close()
	return e.stdout.String()
}

func setupIptables(t *testing.T) error {
	// Clear any existing rules
	exec.Command("iptables", "-t", "nat", "-F").Run()

	// Add REDIRECT rule for all TCP traffic
	cmd := exec.Command("iptables", "-t", "nat", "-A", "OUTPUT",
		"-p", "tcp",
		"-d", testHost,
		"--dport", fmt.Sprintf("%d", testPort),
		"-j", "REDIRECT",
		"--to-port", fmt.Sprintf("%d", testPort))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add TCP redirect rule: %v", err)
	}

	return nil
}

func cleanupIptables(t *testing.T) {
	exec.Command("iptables", "-t", "nat", "-F").Run()
}

func generateTestCertificate(t *testing.T) (string, string) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "spip-e2e-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Generate test certificate using the helper from tls package
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	// Use openssl to generate a self-signed certificate
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", keyPath,
		"-out", certPath,
		"-days", "1",
		"-nodes",
		"-subj", "/CN=localhost")

	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	return certPath, keyPath
}

func createTestConfig(t *testing.T, useTLS bool, certPath, keyPath string) string {
	tmpDir, err := os.MkdirTemp("", "spip-config")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	configPath := filepath.Join(tmpDir, "config.toml")
	var configContent string

	if useTLS {
		configContent = fmt.Sprintf(`
ip = "%s"
port = %d
cert_path = "%s"
key_path = "%s"
`, testHost, testPort, certPath, keyPath)
	} else {
		configContent = fmt.Sprintf(`
ip = "%s"
port = %d
`, testHost, testPort)
	}

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	return configPath
}

func stopSpip(t *testing.T, process *os.Process) {
	if process != nil {
		process.Kill()
		process.Wait()
	}
}

func makeHTTPRequest(t *testing.T, useTLS bool, payload []byte) ([]byte, error) {
	var url string
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	if useTLS {
		url = fmt.Sprintf("https://%s:%d", testHost, testPort)
	} else {
		url = fmt.Sprintf("http://%s:%d", testHost, testPort)
	}

	resp, err := client.Post(url, "text/plain", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func makeTCPRequest(t *testing.T, useTLS bool, payload []byte) ([]byte, error) {
	var conn net.Conn
	var err error
	addr := fmt.Sprintf("%s:%d", testHost, testPort)
	if useTLS {
		conn, err = tls.Dial("tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}

	response := make([]byte, len(payload))
	n, err := conn.Read(response)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return response[:n], nil
}

func TestTCPConnection(t *testing.T) {
	env := setupTestEnv(t, false)
	defer env.cleanup()

	// Test simple TCP connection
	payload := []byte("Hello TCP!")
	response, err := makeTCPRequest(t, false, payload)
	if err != nil {
		t.Fatalf("Failed to make TCP request: %v", err)
	}

	if !bytes.Equal(response, payload) {
		t.Errorf("Got response %q, want %q", string(response), string(payload))
	}

	// Give a small time for output to be written
	time.Sleep(100 * time.Millisecond)

	// Read and validate JSON output
	output := env.getStdout()
	lines := strings.Split(output, "\n")
	var foundPayload bool

	for _, line := range lines {
		if line == "" {
			continue
		}

		entry, err := ParseLogLine(line)
		if err != nil {
			t.Errorf("Failed to parse JSON line %q: %v", line, err)
			continue
		}

		if entry.Payload == string(payload) {
			foundPayload = true
			// Validate JSON structure
			if err := ValidateLogEntry(entry, string(payload), false); err != nil {
				t.Errorf("Invalid JSON structure: %v", err)
			}
			break
		}
	}

	if !foundPayload {
		t.Error("Did not find expected payload in JSON output")
	}

	// Test HTTP over TCP
	httpPayload := []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
	response, err = makeHTTPRequest(t, false, httpPayload)
	if err != nil {
		t.Fatalf("Failed to make HTTP request: %v", err)
	}

	if len(response) == 0 {
		t.Error("Expected non-empty HTTP response")
	}
}

func TestTLSConnection(t *testing.T) {
	env := setupTestEnv(t, true)
	defer env.cleanup()

	// Test simple TLS connection
	payload := []byte("Hello TLS!")
	response, err := makeTCPRequest(t, true, payload)
	if err != nil {
		t.Fatalf("Failed to make TLS request: %v", err)
	}

	if !bytes.Equal(response, payload) {
		t.Errorf("Got response %q, want %q", string(response), string(payload))
	}

	// Test HTTPS
	httpsPayload := []byte("POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\n\r\nHello HTTPS!")
	response, err = makeHTTPRequest(t, true, httpsPayload)
	if err != nil {
		t.Fatalf("Failed to make HTTPS request: %v", err)
	}

	if len(response) == 0 {
		t.Error("Expected non-empty HTTPS response")
	}
}

func TestConcurrentConnections(t *testing.T) {
	env := setupTestEnv(t, true)
	defer env.cleanup()

	// Test concurrent TCP and TLS connections
	const numConnections = 10
	errChan := make(chan error, numConnections*2)
	doneChan := make(chan struct{})

	// Start TCP connections
	for i := 0; i < numConnections; i++ {
		go func(id int) {
			payload := []byte(fmt.Sprintf("TCP request %d", id))
			response, err := makeTCPRequest(t, false, payload)
			if err != nil {
				errChan <- fmt.Errorf("TCP request %d failed: %v", id, err)
				return
			}
			if !bytes.Equal(response, payload) {
				errChan <- fmt.Errorf("TCP request %d: got %q, want %q", id, string(response), string(payload))
				return
			}
			errChan <- nil
		}(i)
	}

	// Start TLS connections
	for i := 0; i < numConnections; i++ {
		go func(id int) {
			payload := []byte(fmt.Sprintf("TLS request %d", id))
			response, err := makeTCPRequest(t, true, payload)
			if err != nil {
				errChan <- fmt.Errorf("TLS request %d failed: %v", id, err)
				return
			}
			if !bytes.Equal(response, payload) {
				errChan <- fmt.Errorf("TLS request %d: got %q, want %q", id, string(response), string(payload))
				return
			}
			errChan <- nil
		}(i)
	}

	// Wait for all connections to complete
	go func() {
		for i := 0; i < numConnections*2; i++ {
			if err := <-errChan; err != nil {
				t.Error(err)
			}
		}
		close(doneChan)
	}()

	select {
	case <-doneChan:
		// All connections completed successfully
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for concurrent connections")
	}
}

func TestLongRunningConnection(t *testing.T) {
	env := setupTestEnv(t, true)
	defer env.cleanup()

	// Create a long-running connection
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", testHost, testPort), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to create long-running connection: %v", err)
	}
	defer conn.Close()

	// Send multiple messages over the same connection
	for i := 0; i < 5; i++ {
		payload := []byte(fmt.Sprintf("Message %d", i))
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("Failed to write message %d: %v", i, err)
		}

		response := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, response); err != nil {
			t.Fatalf("Failed to read response for message %d: %v", i, err)
		}

		if !bytes.Equal(response, payload) {
			t.Errorf("Message %d: got %q, want %q", i, string(response), string(payload))
		}

		time.Sleep(100 * time.Millisecond)
	}
}

func TestConnectionReset(t *testing.T) {
	env := setupTestEnv(t, true)
	defer env.cleanup()

	// Test connection reset handling
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", testHost, testPort))
	if err != nil {
		t.Fatalf("Failed to create connection: %v", err)
	}

	// Send partial data and close immediately
	conn.Write([]byte("Partial"))
	conn.Close()

	// Wait a bit and try a new connection
	time.Sleep(100 * time.Millisecond)

	payload := []byte("New connection")
	response, err := makeTCPRequest(t, false, payload)
	if err != nil {
		t.Fatalf("Failed to make request after reset: %v", err)
	}

	if !bytes.Equal(response, payload) {
		t.Errorf("After reset: got %q, want %q", string(response), string(payload))
	}
}

func TestProcessRestart(t *testing.T) {
	env := setupTestEnv(t, true)

	// Make initial request
	payload := []byte("Before restart")
	response, err := makeTCPRequest(t, true, payload)
	if err != nil {
		t.Fatalf("Failed to make request before restart: %v", err)
	}

	if !bytes.Equal(response, payload) {
		t.Errorf("Before restart: got %q, want %q", string(response), string(payload))
	}

	// Stop the process
	stopSpip(t, env.spipProcess)
	env.spipProcess = nil

	// Start a new process
	var stdout *bytes.Buffer
	env.spipProcess, stdout, env.stdoutPipe = startSpip(t, env.configPath)
	env.stdout = stdout

	// Wait for the new process to start
	time.Sleep(2 * time.Second)

	// Make another request
	payload = []byte("After restart")
	response, err = makeTCPRequest(t, true, payload)
	if err != nil {
		t.Fatalf("Failed to make request after restart: %v", err)
	}

	if !bytes.Equal(response, payload) {
		t.Errorf("After restart: got %q, want %q", string(response), string(payload))
	}

	env.cleanup()
}

func TestOriginalDestinationPreservationTCP(t *testing.T) {
	env := setupTestEnv(t, false)
	defer env.cleanup()

	// Setup iptables rules to redirect multiple ports
	ports := []int{22, 80, 443, 3306, 5432}
	for _, port := range ports {
		cmd := exec.Command("iptables", "-t", "nat", "-A", "OUTPUT",
			"-p", "tcp",
			"-d", testHost,
			"--dport", fmt.Sprintf("%d", port),
			"-j", "REDIRECT",
			"--to-port", fmt.Sprintf("%d", testPort))
		if err := cmd.Run(); err != nil {
			t.Fatalf("Failed to add iptables rule for port %d: %v", port, err)
		}
	}

	// Test connections to different ports
	type testConn struct {
		port    int
		payload string
	}

	testCases := make([]testConn, len(ports))
	for i, port := range ports {
		testCases[i] = testConn{
			port:    port,
			payload: fmt.Sprintf("Test TCP connection to port %d", port),
		}
	}

	// Track which ports we've found with correct data
	foundPorts := make(map[int]bool)
	portPayloads := make(map[int]string)
	portSessions := make(map[int]string)

	// Make connections and track session IDs
	for _, tc := range testCases {
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", testHost, tc.port))
		if err != nil {
			t.Fatalf("Failed to connect to port %d: %v", tc.port, err)
		}

		if _, err := conn.Write([]byte(tc.payload)); err != nil {
			t.Fatalf("Failed to write to port %d: %v", tc.port, err)
		}

		// Read response
		response := make([]byte, len(tc.payload))
		if _, err := io.ReadFull(conn, response); err != nil {
			t.Fatalf("Failed to read from port %d: %v", tc.port, err)
		}

		if !bytes.Equal(response, []byte(tc.payload)) {
			t.Errorf("Port %d: response mismatch", tc.port)
		}

		conn.Close()
	}

	// Wait for output to be written
	time.Sleep(time.Second)

	// Read and verify the JSON output
	output := env.getStdout()
	lines := strings.Split(output, "\n")

	// Verify each port appears in the output with correct original destination
	for _, line := range lines {
		if line == "" {
			continue
		}

		entry, err := ParseLogLine(line)
		if err != nil {
			t.Errorf("Failed to parse JSON line %q: %v", line, err)
			continue
		}

		// Look for connection entries that match our test cases
		if entry.DestinationPort != 0 {
			// Verify this was one of our test ports
			for _, tc := range testCases {
				if entry.DestinationPort == tc.port {
					// Verify all fields for this connection
					if entry.Payload != tc.payload {
						t.Errorf("Port %d: payload mismatch: got %q, want %q", tc.port, entry.Payload, tc.payload)
					}
					if entry.SourceIP != testHost {
						t.Errorf("Port %d: source IP mismatch: got %q, want %q", tc.port, entry.SourceIP, testHost)
					}
					if entry.DestinationIP != testHost {
						t.Errorf("Port %d: destination IP mismatch: got %q, want %q", tc.port, entry.DestinationIP, testHost)
					}
					if entry.IsTLS {
						t.Errorf("Port %d: connection incorrectly marked as TLS", tc.port)
					}
					if entry.SessionID == "" {
						t.Errorf("Port %d: missing session ID", tc.port)
					}
					foundPorts[tc.port] = true
					portPayloads[tc.port] = entry.Payload
					portSessions[tc.port] = entry.SessionID
				}
			}
		}
	}

	// Verify we found all ports with correct data
	for _, tc := range testCases {
		if !foundPorts[tc.port] {
			t.Errorf("Did not find connection to original port %d in output", tc.port)
		}
		if payload := portPayloads[tc.port]; payload != tc.payload {
			t.Errorf("Port %d: final payload mismatch: got %q, want %q", tc.port, payload, tc.payload)
		}
		if session := portSessions[tc.port]; session == "" {
			t.Errorf("Port %d: missing session ID in final verification", tc.port)
		}
	}
}

func TestOriginalDestinationPreservationTLS(t *testing.T) {
	env := setupTestEnv(t, true)
	defer env.cleanup()

	// Setup iptables rules to redirect multiple ports
	ports := []int{443, 8443, 9443} // Common HTTPS ports
	for _, port := range ports {
		cmd := exec.Command("iptables", "-t", "nat", "-A", "OUTPUT",
			"-p", "tcp",
			"-d", testHost,
			"--dport", fmt.Sprintf("%d", port),
			"-j", "REDIRECT",
			"--to-port", fmt.Sprintf("%d", testPort))
		if err := cmd.Run(); err != nil {
			t.Fatalf("Failed to add iptables rule for port %d: %v", port, err)
		}
	}

	// Test connections to different ports
	type testConn struct {
		port    int
		payload string
	}

	testCases := make([]testConn, len(ports))
	for i, port := range ports {
		testCases[i] = testConn{
			port:    port,
			payload: fmt.Sprintf("Test TLS connection to port %d", port),
		}
	}

	// Create synchronized maps for storing results
	var mu sync.Mutex
	foundPorts := make(map[int]bool)
	portPayloads := make(map[int]string)
	portSessions := make(map[int]string)

	// Make connections and track session IDs
	var wg sync.WaitGroup
	for _, tc := range testCases {
		wg.Add(1)
		go func(tc testConn) {
			defer wg.Done()

			// Configure TLS client to skip all verification
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
			}

			// Connect using TLS
			conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", testHost, tc.port), tlsConfig)
			if err != nil {
				t.Errorf("Failed to connect to port %d: %v", tc.port, err)
				return
			}
			defer conn.Close()

			if _, err := conn.Write([]byte(tc.payload)); err != nil {
				t.Errorf("Failed to write to port %d: %v", tc.port, err)
				return
			}

			// Read response
			response := make([]byte, len(tc.payload))
			if _, err := io.ReadFull(conn, response); err != nil {
				t.Errorf("Failed to read from port %d: %v", tc.port, err)
				return
			}

			if !bytes.Equal(response, []byte(tc.payload)) {
				t.Errorf("Port %d: response mismatch", tc.port)
			}
		}(tc)
	}

	// Wait for all connections to complete
	wg.Wait()

	// Wait for output to be written
	time.Sleep(time.Second)

	// Read and verify the JSON output
	output := env.getStdout()
	lines := strings.Split(output, "\n")

	// Verify each port appears in the output with correct original destination
	for _, line := range lines {
		if line == "" {
			continue
		}

		entry, err := ParseLogLine(line)
		if err != nil {
			t.Errorf("Failed to parse JSON line %q: %v", line, err)
			continue
		}

		// Look for connection entries that match our test cases
		if entry.DestinationPort != 0 {
			// Verify this was one of our test ports
			for _, tc := range testCases {
				if entry.DestinationPort == tc.port {
					// Verify all fields for this connection
					if entry.Payload != tc.payload {
						t.Errorf("Port %d: payload mismatch: got %q, want %q", tc.port, entry.Payload, tc.payload)
					}
					if entry.SourceIP != testHost {
						t.Errorf("Port %d: source IP mismatch: got %q, want %q", tc.port, entry.SourceIP, testHost)
					}
					if entry.DestinationIP != testHost {
						t.Errorf("Port %d: destination IP mismatch: got %q, want %q", tc.port, entry.DestinationIP, testHost)
					}
					if !entry.IsTLS {
						t.Errorf("Port %d: connection not marked as TLS", tc.port)
					}
					if entry.SessionID == "" {
						t.Errorf("Port %d: missing session ID", tc.port)
					}
					mu.Lock()
					foundPorts[tc.port] = true
					portPayloads[tc.port] = entry.Payload
					portSessions[tc.port] = entry.SessionID
					mu.Unlock()
				}
			}
		}
	}

	// Verify we found all ports with correct data
	for _, tc := range testCases {
		mu.Lock()
		found := foundPorts[tc.port]
		payload := portPayloads[tc.port]
		session := portSessions[tc.port]
		mu.Unlock()

		if !found {
			t.Errorf("Did not find connection to original port %d in output", tc.port)
		}
		if payload != tc.payload {
			t.Errorf("Port %d: final payload mismatch: got %q, want %q", tc.port, payload, tc.payload)
		}
		if session == "" {
			t.Errorf("Port %d: missing session ID in final verification", tc.port)
		}
	}
}

func TestHighLoadConcurrent(t *testing.T) {
	env := setupTestEnv(t, true)
	defer env.cleanup()

	// Test parameters - reduced load for test environments
	const (
		totalDuration = 15 * time.Second // Increased timeout
		ratePerSecond = 4                // 4 connections per second
		totalConns    = 20               // Total connections to make
	)

	// Create channels for error reporting and completion signaling
	errChan := make(chan error, totalConns*2) // For both TCP and TLS
	doneChan := make(chan struct{})

	// Start connection maker at regular intervals
	ticker := time.NewTicker(time.Second / time.Duration(ratePerSecond))
	defer ticker.Stop()

	connCount := 0
	start := time.Now()

	for connCount < totalConns {
		<-ticker.C

		// TCP goroutine
		go func(id int) {
			payload := []byte(fmt.Sprintf("TCP probe %d", id))
			response, err := makeTCPRequest(t, false, payload)
			if err != nil {
				errChan <- fmt.Errorf("TCP probe %d failed: %v", id, err)
				return
			}
			if !bytes.Equal(response, payload) {
				errChan <- fmt.Errorf("TCP probe %d: response mismatch", id)
			}
			errChan <- nil
		}(connCount)

		// TLS goroutine
		go func(id int) {
			payload := []byte(fmt.Sprintf("TLS probe %d", id))
			response, err := makeTCPRequest(t, true, payload)
			if err != nil {
				errChan <- fmt.Errorf("TLS probe %d failed: %v", id, err)
				return
			}
			if !bytes.Equal(response, payload) {
				errChan <- fmt.Errorf("TLS probe %d: response mismatch", id)
			}
			errChan <- nil
		}(connCount)

		connCount++
	}

	// Start error collector
	go func() {
		for i := 0; i < totalConns*2; i++ {
			if err := <-errChan; err != nil {
				t.Error(err)
			}
		}
		close(doneChan)
	}()

	// Wait for all connections to complete
	select {
	case <-doneChan:
		duration := time.Since(start)
		t.Logf("Completed %d connections in %v (rate: %.2f/sec)",
			totalConns*2, duration, float64(totalConns*2)/duration.Seconds())
	case <-time.After(totalDuration):
		t.Fatal("Test timed out")
	}
}
