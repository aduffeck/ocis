package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/owncloud/ocis/v2/ocis-pkg/log"
)

var (
	defaultHosts = []string{"127.0.0.1", "localhost"}
)

// GenCert generates TLS-Certificates. This function has side effects: it creates the respective certificate / key pair at
// the destination locations unless the tuple already exists, if that is the case, this is a noop.
func GenCert(address, certName, keyName, rootCA, rootKey string, l log.Logger) error {

	_, certErr := os.Stat(certName)
	_, keyErr := os.Stat(keyName)

	if certErr == nil || keyErr == nil {
		l.Info().Msg(
			fmt.Sprintf("%v certificate / key pair already present. skipping acme certificate generation",
				filepath.Base(certName)))
		return nil
	}

	cert, key, err := CertKeyPair(address, rootCA, rootKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certName), 0755); err != nil {
		l.Fatal().Err(err).Msg("failed to store certificate")
		return err
	}
	if err := os.WriteFile(certName, []byte(cert), 0600); err != nil {
		l.Fatal().Err(err).Msg("failed to store certificate")
		return err
	}
	if err := os.WriteFile(keyName, []byte(key), 0600); err != nil {
		l.Fatal().Err(err).Msg("failed to store key")
		return err
	}

	return nil
}

// CertKeyPair generates temporary cert/key pair in memory.
func CertKeyPair(addr, rootCAPEM, rootKeyPEM string) ([]byte, []byte, error) {
	block, _ := pem.Decode([]byte(rootCAPEM))
	if block == nil {
		return nil, nil, fmt.Errorf("invalid internal root CA")
	}
	rootCA, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	block, _ = pem.Decode([]byte(rootKeyPEM))
	if block == nil {
		return nil, nil, fmt.Errorf("invalid internal root key")
	}
	rootKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	subjects := defaultHosts
	if host, _, err := net.SplitHostPort(addr); err == nil && host != "" && host != "0.0.0.0" && host != "127.0.0.1" {
		subjects = []string{host}
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	cert := &x509.Certificate{
		Issuer:       rootCA.Subject,
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Company, INC."},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	for _, h := range subjects {
		if ip := net.ParseIP(h); ip != nil {
			cert.IPAddresses = append(cert.IPAddresses, ip)
		} else {
			cert.DNSNames = append(cert.DNSNames, h)
		}
	}

	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, rootCA, &certPrivKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}

	// Sign certificate

	// create public key
	certOut := bytes.NewBuffer(nil)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	// create private key
	keyOut := bytes.NewBuffer(nil)
	b, err := x509.MarshalECPrivateKey(certPrivKey)
	if err != nil {
		return nil, nil, err
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b})

	return certOut.Bytes(), keyOut.Bytes(), nil
}

// GenTempCertForAddr generates temporary TLS-Certificates in memory.
func GenTempCertForAddr(addr, rootCAPEM, rootKeyPEM string) (tls.Certificate, error) {
	cert, key, err := CertKeyPair(addr, rootCAPEM, rootKeyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(cert, key)
}

// persistCertificate generates a certificate using pk as private key and proceeds to store it into a file named certName.
func persistCertificate(certName string, l log.Logger, parent *x509.Certificate, pk interface{}) error {
	if err := ensureExistsDir(certName); err != nil {
		return fmt.Errorf("creating certificate destination: " + certName)
	}

	certificate, err := generateCertificate(parent, pk)
	if err != nil {
		return fmt.Errorf("creating certificate: " + filepath.Dir(certName))
	}

	certOut, err := os.Create(certName)
	if err != nil {
		return fmt.Errorf("failed to open `%v` for writing", certName)
	}

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if err != nil {
		return fmt.Errorf("failed to encode certificate")
	}

	err = certOut.Close()
	if err != nil {
		return fmt.Errorf("failed to write cert")
	}
	l.Info().Msg(fmt.Sprintf("written certificate to %v", certName))

	return nil
}

// genCert generates a self signed certificate using a random rsa key.
func generateCertificate(parent *x509.Certificate, pk interface{}) ([]byte, error) {
	for _, h := range defaultHosts {
		if ip := net.ParseIP(h); ip != nil {
			acmeTemplate.IPAddresses = append(acmeTemplate.IPAddresses, ip)
		} else {
			acmeTemplate.DNSNames = append(acmeTemplate.DNSNames, h)
		}
	}

	return x509.CreateCertificate(rand.Reader, &acmeTemplate, &acmeTemplate, publicKey(pk), pk)
}

// persistKey persists the private key used to generate the certificate at the configured location.
func persistKey(destination string, l log.Logger, pk interface{}) error {
	if err := ensureExistsDir(destination); err != nil {
		return fmt.Errorf("creating key destination: " + destination)
	}

	keyOut, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %v for writing", destination)
	}
	err = pem.Encode(keyOut, pemBlockForKey(pk, l))
	if err != nil {
		return fmt.Errorf("failed to encode key")
	}

	err = keyOut.Close()
	if err != nil {
		return fmt.Errorf("failed to write key")
	}
	l.Info().Msg(fmt.Sprintf("written key to %v", destination))

	return nil
}

func publicKey(pk interface{}) interface{} {
	switch k := pk.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(pk interface{}, l log.Logger) *pem.Block {
	switch k := pk.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			l.Fatal().Err(err).Msg("Unable to marshal ECDSA private key")
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func ensureExistsDir(uri string) error {
	certPath := filepath.Dir(uri)
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		err = os.MkdirAll(certPath, 0700)
		if err != nil {
			return err
		}
	}
	return nil
}
