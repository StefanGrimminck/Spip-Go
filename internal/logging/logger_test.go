package logging

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestLogMessage(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "spip-log-test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	logger := NewLogger(tmpFile)

	// Test each log level
	tests := []struct {
		level   LogLevel
		target  string
		message string
	}{
		{LevelDebug, "test", "debug message"},
		{LevelInfo, "test", "info message"},
		{LevelWarn, "test", "warning message"},
		{LevelError, "test", "error message"},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			err := logger.Log(tt.level, tt.target, tt.message)
			if err != nil {
				t.Errorf("Log() error = %v", err)
				return
			}
		})
	}

	// Reset file pointer to beginning
	if _, err := tmpFile.Seek(0, 0); err != nil {
		t.Fatalf("Failed to seek file: %v", err)
	}

	// Read and verify log entries
	decoder := json.NewDecoder(tmpFile)
	for _, tt := range tests {
		var logMsg LogMessage
		if err := decoder.Decode(&logMsg); err != nil {
			t.Fatalf("Failed to decode log message: %v", err)
		}

		if logMsg.Level != tt.level {
			t.Errorf("Log level = %v, want %v", logMsg.Level, tt.level)
		}
		if logMsg.Target != tt.target {
			t.Errorf("Log target = %v, want %v", logMsg.Target, tt.target)
		}
		if logMsg.Message != tt.message {
			t.Errorf("Log message = %v, want %v", logMsg.Message, tt.message)
		}
		if logMsg.RecordType != "log" {
			t.Errorf("Log record type = %v, want 'log'", logMsg.RecordType)
		}
	}
}

func TestLogConnection(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "spip-conn-test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	logger := NewLogger(tmpFile)

	// Test connection data logging
	connData := &ConnectionData{
		Timestamp:       time.Now().Unix(),
		Payload:         "test payload",
		PayloadHex:      "74657374207061796c6f6164",
		SourceIP:        "127.0.0.1",
		SourcePort:      12345,
		DestinationIP:   "192.168.1.1",
		DestinationPort: 80,
		SessionID:       "test-session",
		IsTLS:           true,
	}

	if err := logger.LogConnection(connData); err != nil {
		t.Fatalf("LogConnection() error = %v", err)
	}

	// Reset file pointer to beginning
	if _, err := tmpFile.Seek(0, 0); err != nil {
		t.Fatalf("Failed to seek file: %v", err)
	}

	// Read and verify connection data
	var loggedConn ConnectionData
	decoder := json.NewDecoder(tmpFile)
	if err := decoder.Decode(&loggedConn); err != nil {
		t.Fatalf("Failed to decode connection data: %v", err)
	}

	if loggedConn.Payload != connData.Payload {
		t.Errorf("Connection payload = %v, want %v", loggedConn.Payload, connData.Payload)
	}
	if loggedConn.PayloadHex != connData.PayloadHex {
		t.Errorf("Connection payload hex = %v, want %v", loggedConn.PayloadHex, connData.PayloadHex)
	}
	if loggedConn.SourceIP != connData.SourceIP {
		t.Errorf("Connection source IP = %v, want %v", loggedConn.SourceIP, connData.SourceIP)
	}
	if loggedConn.SourcePort != connData.SourcePort {
		t.Errorf("Connection source port = %v, want %v", loggedConn.SourcePort, connData.SourcePort)
	}
	if loggedConn.DestinationIP != connData.DestinationIP {
		t.Errorf("Connection destination IP = %v, want %v", loggedConn.DestinationIP, connData.DestinationIP)
	}
	if loggedConn.DestinationPort != connData.DestinationPort {
		t.Errorf("Connection destination port = %v, want %v", loggedConn.DestinationPort, connData.DestinationPort)
	}
	if loggedConn.SessionID != connData.SessionID {
		t.Errorf("Connection session ID = %v, want %v", loggedConn.SessionID, connData.SessionID)
	}
	if loggedConn.IsTLS != connData.IsTLS {
		t.Errorf("Connection TLS status = %v, want %v", loggedConn.IsTLS, connData.IsTLS)
	}
}

func TestLoggerHelperFunctions(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf)

	tests := []struct {
		name    string
		logFunc func(string, string)
		level   LogLevel
		target  string
		message string
	}{
		{"Debug", logger.Debug, LevelDebug, "test", "debug message"},
		{"Info", logger.Info, LevelInfo, "test", "info message"},
		{"Warn", logger.Warn, LevelWarn, "test", "warning message"},
		{"Error", logger.Error, LevelError, "test", "error message"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			tt.logFunc(tt.target, tt.message)

			var logMsg LogMessage
			if err := json.NewDecoder(&buf).Decode(&logMsg); err != nil {
				t.Fatalf("Failed to decode log message: %v", err)
			}

			if logMsg.Level != tt.level {
				t.Errorf("Log level = %v, want %v", logMsg.Level, tt.level)
			}
			if logMsg.Target != tt.target {
				t.Errorf("Log target = %v, want %v", logMsg.Target, tt.target)
			}
			if logMsg.Message != tt.message {
				t.Errorf("Log message = %v, want %v", logMsg.Message, tt.message)
			}
		})
	}
}
