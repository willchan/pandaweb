package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/gorilla/handlers"
	"github.com/willchan/pandaweb"
)

var (
	httpsPort = flag.Int("https_port", -1, "https port to listen to")
	httpPort  = flag.Int("http_port", -1, "http port to listen to, which redirects to the https port")
	webRoot   = flag.String("webroot", "", "root directory for web file serving")
	certFile  = flag.String("certfile", "", "path to certificate chain file")
	keyFile   = flag.String("keyfile", "", "path to private key file")
)

func redirectHttpHttps(w http.ResponseWriter, r *http.Request) {
	u := r.URL
	u.Scheme = "https"
	if strings.Index(r.Host, ":") != -1 {
		var err error
		u.Host, _, err = net.SplitHostPort(r.Host)
		if err != nil {
			fmt.Println("err: ", err)
			http.NotFound(w, r)
			return
		}
	} else {
		u.Host = r.Host
	}
	if *httpsPort != 443 {
		u.Host = net.JoinHostPort(u.Host, strconv.Itoa(*httpsPort))
	}
	http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
}

func main() {
	flag.Parse()

	if *httpsPort < 0 || *httpsPort >= 1<<16 {
		fmt.Println("-https_port has invalid port:", *httpsPort)
		os.Exit(1)
	}
	if *httpPort < 0 || *httpPort >= 1<<16 {
		fmt.Println("-http_port has invalid port:", *httpPort)
		os.Exit(1)
	}
	if _, err := os.Stat(*webRoot); os.IsNotExist(err) {
		fmt.Println("-webroot is invalid path")
		os.Exit(1)
	}

	cm := &pandaweb.CertificateManager{}
	if err := cm.LoadX509KeyPair(*certFile, *keyFile); err != nil {
		fmt.Println("Failed to load TLS certificate:", err)
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)

	gc := func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return cm.GetCertificate(clientHello)
	}

	// Start up the HTTPS server.
	http.Handle("/", handlers.LoggingHandler(os.Stdout, http.FileServer(http.Dir(*webRoot))))
	srv := &http.Server{
		Addr: fmt.Sprintf(":%d", *httpsPort),
		TLSConfig: &tls.Config{
			GetCertificate: gc,
		},
	}
	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			fmt.Println("Failed to listen and serve:", err)
			os.Exit(1)
		}
	}()

	// Start up the HTTP server and have it redirect to HTTPS.
	go func() {
		if err := http.ListenAndServe(fmt.Sprintf(":%d", *httpPort), http.HandlerFunc(redirectHttpHttps)); err != nil {
			fmt.Println("Failed to listen and serve:", err)
			os.Exit(1)
		}
	}()

	fmt.Printf("pandaweb is running on https port %d and http port %d...\n", *httpsPort, *httpPort)

	for _ = range sigChan {
		log.Printf("Reloading TLS certificate")
		if err := cm.LoadX509KeyPair(*certFile, *keyFile); err != nil {
			log.Println("Failed to reload TLS certificate:", err)
		}
	}
}
