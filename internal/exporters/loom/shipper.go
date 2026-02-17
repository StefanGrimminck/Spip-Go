package loom

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"spip/internal/config"
)

const (
	channelCapacity = 256
	clientTimeout   = 15 * time.Second
)

type Shipper struct {
	cfg     *config.LoomConfig
	client  *http.Client
	inCh    chan map[string]interface{}
	done    chan struct{}
	onError func(string)
}

func NewShipper(cfg *config.LoomConfig, onError func(string)) *Shipper {
	var transport http.RoundTripper = http.DefaultTransport
	if cfg.InsecureSkipVerify {
		transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	client := &http.Client{Timeout: clientTimeout, Transport: transport}
	return &Shipper{
		cfg:     cfg,
		client:  client,
		inCh:    make(chan map[string]interface{}, channelCapacity),
		done:    make(chan struct{}),
		onError: onError,
	}
}

func (s *Shipper) Run() (chan<- map[string]interface{}, <-chan struct{}) {
	var batch []map[string]interface{}
	flush := func() {
		if len(batch) == 0 {
			return
		}
		body, err := json.Marshal(batch)
		if err != nil {
			s.onError(fmt.Sprintf("loom marshal: %v", err))
			batch = nil
			return
		}
		req, err := http.NewRequest(http.MethodPost, s.cfg.URL, bytes.NewReader(body))
		if err != nil {
			s.onError(fmt.Sprintf("loom request: %v", err))
			batch = nil
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Spip-ID", s.cfg.SensorID)
		req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
		resp, err := s.client.Do(req)
		if err != nil {
			s.onError(fmt.Sprintf("loom POST: %v", err))
			batch = nil
			return
		}
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			s.onError(fmt.Sprintf("loom POST: status %d", resp.StatusCode))
		}
		batch = nil
	}

	go func() {
		defer close(s.done)
		ticker := time.NewTicker(s.cfg.FlushIntervalDuration())
		defer ticker.Stop()
		for {
			select {
			case ev, ok := <-s.inCh:
				if !ok {
					flush()
					return
				}
				batch = append(batch, ev)
				if len(batch) >= s.cfg.BatchSize {
					flush()
				}
			case <-ticker.C:
				flush()
			}
		}
	}()

	return s.inCh, s.done
}

func (s *Shipper) Shutdown() {
	close(s.inCh)
	<-s.done
}
