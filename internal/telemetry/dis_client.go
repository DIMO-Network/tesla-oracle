package telemetry

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
)

type Sender interface {
	Send(ctx context.Context, data []byte) error
}

type DISClient struct {
	host                *url.URL
	client              *http.Client
	retry               int
	retryBackoffSeconds int
	logger              *zerolog.Logger
}

func NewDISClient(clientTLSCert, clientTLSKey, caCert, host string, retryBackoffSeconds int, retry int, logger *zerolog.Logger) (*DISClient, error) {
	disCert, err := tls.X509KeyPair([]byte(clientTLSCert), []byte(clientTLSKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create cert key pair: %w", err)
	}

	disCertPool := x509.NewCertPool()
	if ok := disCertPool.AppendCertsFromPEM([]byte(caCert)); !ok {
		return nil, fmt.Errorf("failed to parse certificates")
	}

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{disCert},
		RootCAs:      disCertPool,
	}

	parsedURL, err := url.ParseRequestURI(host)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url: %w", err)
	}

	return &DISClient{
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tlsConfig,
			},
			Timeout: 30 * time.Second,
		},
		retry:               retry,
		retryBackoffSeconds: retryBackoffSeconds,
		host:                parsedURL,
		logger:              logger,
	}, nil
}

func (d *DISClient) Send(ctx context.Context, data []byte) error {
	timer := prometheus.NewTimer(batchRequestDuration)
	defer timer.ObserveDuration()

	for i := 0; i < d.retry; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.host.String(), bytes.NewBuffer(data))
		if err != nil {
			return err
		}

		resp, err := d.client.Do(req)
		if err != nil {
			d.logger.Err(err).Int("retryAttempt", i).Msgf("failed to send http request to DIS. retrying in %d seconds", d.retryBackoffSeconds)
			time.Sleep(time.Duration(d.retryBackoffSeconds) * time.Second)
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			disRequestCount.WithLabelValues("Success").Inc()
			return nil
		}

		if resp.StatusCode < http.StatusInternalServerError {
			err := fmt.Errorf("invalid status code, not retrying: %d", resp.StatusCode)
			d.logger.Err(err).Msg("failed to send to DIS")
			return nil
		}

		time.Sleep(time.Duration(d.retryBackoffSeconds) * time.Second)
	}

	return fmt.Errorf("failed to send data to DIS: retry limit %d exceeded", d.retry)
}
