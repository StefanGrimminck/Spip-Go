package e2e

import (
	"encoding/json"
	"fmt"
)

// LogEntry represents the JSON log format output by the SPIP agent
type LogEntry struct {
	Timestamp       int64  `json:"timestamp"`
	Level           string `json:"level,omitempty"`
	Message         string `json:"message,omitempty"`
	Target          string `json:"target,omitempty"`
	RecordType      string `json:"record_type,omitempty"`
	Payload         string `json:"payload,omitempty"`
	PayloadHex      string `json:"payload_hex,omitempty"`
	SourceIP        string `json:"source_ip,omitempty"`
	SourcePort      int    `json:"source_port,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	DestinationPort int    `json:"destination_port,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
	IsTLS           bool   `json:"is_tls,omitempty"`
	TLSVersion      string `json:"tls_version,omitempty"`
	TLSCipherSuite  string `json:"tls_cipher_suite,omitempty"`
}

// ValidateLogEntry validates a single log entry against expected values
func ValidateLogEntry(entry *LogEntry, expectedPayload string, expectedIsTLS bool) error {
	if entry == nil {
		return fmt.Errorf("log entry is nil")
	}

	// Basic validation
	if entry.Timestamp == 0 {
		return fmt.Errorf("timestamp is missing")
	}

	if entry.SessionID == "" {
		return fmt.Errorf("session_id is missing")
	}

	// Validate payload if provided
	if expectedPayload != "" && entry.Payload != expectedPayload {
		return fmt.Errorf("payload mismatch: got %q, want %q", entry.Payload, expectedPayload)
	}

	// Validate TLS flag
	if entry.IsTLS != expectedIsTLS {
		return fmt.Errorf("TLS flag mismatch: got %v, want %v", entry.IsTLS, expectedIsTLS)
	}

	// Validate IP addresses and ports
	if entry.SourceIP == "" || entry.DestinationIP == "" {
		return fmt.Errorf("source or destination IP is missing")
	}

	if entry.SourcePort == 0 || entry.DestinationPort == 0 {
		return fmt.Errorf("source or destination port is missing")
	}

	return nil
}

// ParseLogLine parses a JSON log line into a LogEntry struct
func ParseLogLine(line string) (*LogEntry, error) {
	var entry LogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}
