package pandaweb

import (
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
)

// CertificateManager manages vending the correct certificate for a given
// ClientHello. It also handles updating certificates (e.g. renewals). Its
// methods are safe for simultaneous use by multiple goroutines.
type CertificateManager struct {
	certificates      []tls.Certificate
	nameToCertificate map[string]*tls.Certificate
	m                 sync.RWMutex
}

// SetCertificates updates the set of certificates. It parses the certificates
// and builds a map from names to certificates based on the CommonName and
// SubjectAlternateName fields of the leaf certificates.
func (cm *CertificateManager) SetCertificates(certificates []tls.Certificate) {
	c := &tls.Config{
		Certificates: certificates,
	}
	c.BuildNameToCertificate()
	cm.m.Lock()
	cm.certificates = certificates
	cm.nameToCertificate = c.NameToCertificate
	cm.m.Unlock()
}

// LoadX509KeyPair updates CertificateManager's certificates from a pair of PEM
// encoded files.
func (cm *CertificateManager) LoadX509KeyPair(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("CertificateManager failed to load X509 key pair: %v", err)
	}
	certs := []tls.Certificate{cert}
	cm.SetCertificates(certs)
	return nil
}

// GetCertificate returns certificate corresponding to the SNI info in the
// ClientHello, or the first certificate if no SNI info is provided. It returns
// nil if it cannot find an appropriate certificate given the SNI info.
func (cm *CertificateManager) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.m.RLock()
	defer cm.m.RUnlock()
	if len(cm.certificates) == 0 {
		return nil, errors.New("CertificateManager does not have any certificates")
	}
	if clientHello.ServerName == "" {
		return &cm.certificates[0], nil
	}

	c, _ := cm.nameToCertificate[clientHello.ServerName]
	return c, nil
}
