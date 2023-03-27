package http

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/owncloud/ocis/v2/ocis-pkg/broker"
	"github.com/owncloud/ocis/v2/ocis-pkg/log"
	"github.com/owncloud/ocis/v2/ocis-pkg/registry"

	mhttps "github.com/go-micro/plugins/v4/server/http"
	crypto "github.com/owncloud/ocis/v2/ocis-pkg/crypto"
	"go-micro.dev/v4"
	"go-micro.dev/v4/server"
	"go-micro.dev/v4/transport"
)

// Service simply wraps the go-micro web service.
type Service struct {
	micro.Service
}

// NewService initializes a new http service.
func NewService(opts ...Option) (Service, error) {
	noopBroker := broker.NoOp{}
	sopts := newOptions(opts...)

	tlsConfig, err := BuildTlsConfig(sopts.Address, sopts.TLSConfig.Cert, sopts.TLSConfig.Key, sopts.InternalRootCA, sopts.InternalRootKey, sopts.Logger)
	if err != nil {
		return Service{}, err
	}

	mServer := mhttps.NewServer(server.TLSConfig(tlsConfig))
	wopts := []micro.Option{
		micro.Server(mServer),
		micro.Broker(noopBroker),
		micro.Address(sopts.Address),
		micro.Name(strings.Join([]string{sopts.Namespace, sopts.Name}, ".")),
		micro.Version(sopts.Version),
		micro.Context(sopts.Context),
		micro.Flags(sopts.Flags...),
		micro.Registry(registry.GetRegistry()),
		micro.RegisterTTL(time.Second * 30),
		micro.RegisterInterval(time.Second * 10),
		micro.Transport(transport.NewHTTPTransport(transport.TLSConfig(tlsConfig))),
	}
	if sopts.TLSConfig.Enabled {
		wopts = append(wopts, micro.Metadata(map[string]string{"use_tls": "true"}))
	}

	return Service{micro.NewService(wopts...)}, nil
}

func BuildTlsConfig(address, certPath, keyPath, rootCA, rootKey string, l log.Logger) (*tls.Config, error) {
	var cert tls.Certificate
	certPool := x509.NewCertPool()

	var err error
	if certPath != "" && keyPath != "" {
		cert, err = tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			l.Error().Err(err).
				Str("cert", certPath).
				Str("key", keyPath).
				Msg("error loading server certifcate and key")
			return nil, fmt.Errorf("error loading server certificate and key: %w", err)
		}
	} else {
		// Generate a self-signed server certificate on the fly
		l.Warn().Str("address", address).
			Msg("No server certificate configured. Generating a temporary self-signed certificate")
		cert, err = crypto.GenTempCertForAddr(address, rootCA, rootKey)
		if err != nil {
			return nil, fmt.Errorf("error creating temporary self-signed certificate: %w", err)
		}
	}

	if rootCA != "" {
		ok := certPool.AppendCertsFromPEM([]byte(rootCA))
		if !ok {
			l.Error().Msg("failed to add the internal root CA to the certpool")
		}
	}

	return &tls.Config{
		NextProtos:   []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
	}, nil
}
