package cmsauth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/user"
	"strings"
	"sync"
	"time"

	"github.com/vkuznet/x509proxy"
)

// TIMEOUT defines timeout for net/url request
var TIMEOUT int

// Token defines access token location
var Token string

// Verbose defines verbosity level
var Verbose int

// TLSCertsRenewInterval controls interval to re-read TLS certs (in seconds)
var TLSCertsRenewInterval time.Duration

// TLSCerts holds TLS certificates for the server
type TLSCertsManager struct {
	Certs  []tls.Certificate
	Expire time.Time
}

// GetCerts return fresh copy of certificates
func (t *TLSCertsManager) GetCerts() ([]tls.Certificate, error) {
	var lock = sync.Mutex{}
	lock.Lock()
	defer lock.Unlock()
	// we'll use existing certs if our window is not expired
	if t.Certs == nil || time.Since(t.Expire) > TLSCertsRenewInterval {
		t.Expire = time.Now()
		if Verbose > 0 {
			log.Printf("read new certs expire=\"%v\" renewal_interval=%v\n", t.Expire, TLSCertsRenewInterval)
		}
		certs, err := TlsCerts()
		if err == nil {
			t.Certs = certs
		} else {
			// to avoid collision between cron obtaining the proxy and
			// this code base if we have error we'll increase interval instead of failure
			if t.Certs != nil {
				ts := time.Now().Add(time.Duration(600 * time.Second))
				if CertExpire(t.Certs).After(ts) {
					t.Expire = ts
				}
			} else {
				log.Fatal("ERROR ", err.Error())
			}
		}
	}
	return t.Certs, nil
}

// CertExpire gets minimum certificate expire from list of certificates
func CertExpire(certs []tls.Certificate) time.Time {
	var notAfter time.Time
	for _, cert := range certs {
		c, e := x509.ParseCertificate(cert.Certificate[0])
		if e == nil {
			notAfter = c.NotAfter
			break
		}
	}
	return notAfter
}

// global TLSCerts manager
var tlsManager TLSCertsManager

// TlsCerts returns X509 certificates
func TlsCerts() ([]tls.Certificate, error) {
	uproxy := os.Getenv("X509_USER_PROXY")
	uckey := os.Getenv("X509_USER_KEY")
	ucert := os.Getenv("X509_USER_CERT")

	// check if /tmp/x509up_u$UID exists, if so setup X509_USER_PROXY env
	u, err := user.Current()
	if err == nil {
		fname := fmt.Sprintf("/tmp/x509up_u%s", u.Uid)
		if _, err := os.Stat(fname); err == nil {
			uproxy = fname
		}
	}
	if Verbose == 1 {
		log.Printf("tls certs, X509_USER_PROXY=%v, X509_USER_KEY=%v, X509_USER_CERT=%v\n", uproxy, uckey, ucert)
	}

	if uproxy == "" && uckey == "" { // user doesn't have neither proxy or user certs
		return nil, nil
	}
	if uproxy != "" {
		// use local implementation of LoadX409KeyPair instead of tls one
		x509cert, err := x509proxy.LoadX509Proxy(uproxy)
		if err != nil {
			return nil, fmt.Errorf("failed to parse X509 proxy: %v", err)
		}
		if Verbose == 1 {
			log.Println("use proxy", uproxy)
		}
		certs := []tls.Certificate{x509cert}
		return certs, nil
	}
	x509cert, err := tls.LoadX509KeyPair(ucert, uckey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user X509 certificate: %v", err)
	}
	if Verbose == 1 {
		log.Println("user key", uckey, "cert", ucert)
	}
	certs := []tls.Certificate{x509cert}
	return certs, nil
}

// ReadToken function to either read file content or return given string
func ReadToken(r string) string {
	if _, err := os.Stat(r); err == nil {
		b, e := os.ReadFile(r)
		if e != nil {
			log.Fatalf("Unable to read data from file: %s, error: %s", r, e)
		}
		return strings.Replace(string(b), "\n", "", -1)
	}
	return r
}

// HttpClient provides cert/token aware HTTP client
func HttpClient() *http.Client {
	var certs []tls.Certificate
	var err error
	if Token == "" { // if there is no token back auth we fall back to x509
		// get X509 certs
		certs, err = tlsManager.GetCerts()
		if err != nil {
			log.Fatal("ERROR ", err.Error())
		}
	}
	timeout := time.Duration(TIMEOUT) * time.Second
	if len(certs) == 0 {
		if TIMEOUT > 0 {
			return &http.Client{Timeout: time.Duration(timeout)}
		}
		return &http.Client{}
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{Certificates: certs,
			InsecureSkipVerify: true},
	}
	if TIMEOUT > 0 {
		return &http.Client{Transport: tr, Timeout: timeout}
	}
	return &http.Client{Transport: tr}
}
