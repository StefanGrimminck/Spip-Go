package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// LogLevel represents the severity of a log message
type LogLevel string

const (
	LevelDebug LogLevel = "DEBUG"
	LevelInfo  LogLevel = "INFO"
	LevelWarn  LogLevel = "WARN"
	LevelError LogLevel = "ERROR"
)

// LogMessage represents a structured log message
type LogMessage struct {
	Timestamp  int64    `json:"timestamp"`
	Level      LogLevel `json:"level"`
	Message    string   `json:"message"`
	Target     string   `json:"target"`
	RecordType string   `json:"record_type"`
}

// ConnectionData represents TCP connection data
type ConnectionData struct {
	// Name of the agent that produced this record (optional)
	Name            string `json:"name,omitempty"`
	Timestamp       int64  `json:"timestamp"`
	Payload         string `json:"payload"`
	PayloadHex      string `json:"payload_hex"`
	SourceIP        string `json:"source_ip"`
	SourcePort      uint16 `json:"source_port"`
	DestinationIP   string `json:"destination_ip"`
	DestinationPort uint16 `json:"destination_port"`
	SessionID       string `json:"session_id"`
	IsTLS           bool   `json:"is_tls"`
}

// Logger defines the interface for logging operations
type Logger interface {
	Log(level LogLevel, target, message string) error
	LogConnection(data *ConnectionData) error
	Debug(target, message string)
	Info(target, message string)
	Warn(target, message string)
	Error(target, message string)
}

// FileLogger handles JSON-formatted logging to a file or other io.Writer
type FileLogger struct {
	output io.Writer
}

// NewLogger creates a new logger instance
func NewLogger(output io.Writer) Logger {
	return &FileLogger{output: output}
}

// Log writes a log message in JSON format
func (l *FileLogger) Log(level LogLevel, target, message string) error {
	logMsg := LogMessage{
		Timestamp:  time.Now().Unix(),
		Level:      level,
		Message:    message,
		Target:     target,
		RecordType: "log",
	}

	return l.writeJSON(logMsg)
}

// LogConnection writes connection data in JSON format
func (l *FileLogger) LogConnection(data *ConnectionData) error {
	// Build an ECS-like record using only available data (no external lookups)
	ecs := make(map[string]interface{})

	// @timestamp in RFC3339 UTC
	ecs["@timestamp"] = time.Unix(data.Timestamp, 0).UTC().Format(time.RFC3339Nano)

	// event.id
	ecs["event"] = map[string]interface{}{
		"id": data.SessionID,
	}

	// source and destination
	ecs["source"] = map[string]interface{}{
		"ip":   data.SourceIP,
		"port": data.SourcePort,
	}
	ecs["destination"] = map[string]interface{}{
		"ip":   data.DestinationIP,
		"port": data.DestinationPort,
	}

	// server hostname from agent name, if present
	if data.Name != "" {
		ecs["server"] = map[string]interface{}{ "hostname": data.Name }
	}

	// network transport/protocol hints (derived from IsTLS)
	network := map[string]interface{}{
		"transport": "tcp",
	}
	if data.IsTLS {
		network["protocol"] = "tls"
	}
	ecs["network"] = network

	// Attempt lightweight HTTP parsing from payload if it resembles an HTTP request
	payload := data.Payload
	if payload != "" {
		// Split headers by CRLF
		lines := strings.Split(payload, "\r\n")
		if len(lines) > 0 {
			// First line: METHOD PATH HTTP/1.1
			parts := strings.SplitN(lines[0], " ", 3)
			if len(parts) >= 2 {
				method := parts[0]
				path := parts[1]
				// Only include HTTP fields if method looks like HTTP verb
				verbs := map[string]bool{"GET":true,"POST":true,"PUT":true,"DELETE":true,"HEAD":true,"OPTIONS":true,"PATCH":true}
				if verbs[method] {
					ecs["http"] = map[string]interface{}{
						"request": map[string]interface{}{"method": method},
					}
					ecs["url"] = map[string]interface{}{
						"path": path,
					}
				}
			}

			// Find User-Agent header
			for _, ln := range lines[1:] {
				if ln == "" { // headers end
					break
				}
				if strings.HasPrefix(strings.ToLower(ln), "user-agent:") {
					ua := strings.TrimSpace(ln[len("user-agent:"):])
					ecs["user_agent"] = map[string]interface{}{
						"original": ua,
					}
					break
				}
			}
		}
	}

	// Preserve raw payload and hex as optional fields (not part of standard ECS but useful)
	ecs["payload"] = data.Payload
	ecs["payload_hex"] = data.PayloadHex

	return l.writeJSON(ecs)
}

// writeJSON writes any value as JSON to the output
func (l *FileLogger) writeJSON(v interface{}) error {
	encoder := json.NewEncoder(l.output)
	if err := encoder.Encode(v); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}
	return nil
}

// Debug logs a debug message
func (l *FileLogger) Debug(target, message string) {
	l.Log(LevelDebug, target, message)
}

// Info logs an info message
func (l *FileLogger) Info(target, message string) {
	l.Log(LevelInfo, target, message)
}

// Warn logs a warning message
func (l *FileLogger) Warn(target, message string) {
	l.Log(LevelWarn, target, message)
}

// Error logs an error message
func (l *FileLogger) Error(target, message string) {
	l.Log(LevelError, target, message)
}
