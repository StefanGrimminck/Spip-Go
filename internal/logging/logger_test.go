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

	// Read and verify ECS-shaped connection data
	var logged map[string]interface{}
	decoder := json.NewDecoder(tmpFile)
	if err := decoder.Decode(&logged); err != nil {
		t.Fatalf("Failed to decode connection data: %v", err)
	}

	// Check event.id
	evt, ok := logged["event"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing event object in logged record")
	}
	if id, _ := evt["id"].(string); id != connData.SessionID {
		t.Errorf("event.id = %v, want %v", id, connData.SessionID)
	}

	// Check source
	src, ok := logged["source"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing source object in logged record")
	}
	if sip, _ := src["ip"].(string); sip != connData.SourceIP {
		t.Errorf("source.ip = %v, want %v", sip, connData.SourceIP)
	}
	if sport, _ := src["port"].(float64); uint16(sport) != connData.SourcePort {
		t.Errorf("source.port = %v, want %v", sport, connData.SourcePort)
	}

	// Check destination
	dst, ok := logged["destination"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing destination object in logged record")
	}
	if dip, _ := dst["ip"].(string); dip != connData.DestinationIP {
		t.Errorf("destination.ip = %v, want %v", dip, connData.DestinationIP)
	}
	if dport, _ := dst["port"].(float64); uint16(dport) != connData.DestinationPort {
		t.Errorf("destination.port = %v, want %v", dport, connData.DestinationPort)
	}

	// Check network.protocol derived from IsTLS
	if netObj, ok := logged["network"].(map[string]interface{}); ok {
		if connData.IsTLS {
			if proto, _ := netObj["protocol"].(string); proto != "tls" {
				t.Errorf("network.protocol = %v, want %v", proto, "tls")
			}
		}
	} else {
		t.Fatalf("missing network object in logged record")
	}

	// Payload and payload_hex preserved
	if p, _ := logged["payload"].(string); p != connData.Payload {
		t.Errorf("payload = %v, want %v", p, connData.Payload)
	}
	if ph, _ := logged["payload_hex"].(string); ph != connData.PayloadHex {
		t.Errorf("payload_hex = %v, want %v", ph, connData.PayloadHex)
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
