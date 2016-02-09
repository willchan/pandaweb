package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/willchan/pandaweb"
)

var (
	port     = flag.Int("port", -1, "port to listen to")
	webRoot  = flag.String("webroot", "", "root directory for web file serving")
	certFile = flag.String("certfile", "", "path to certificate chain file")
	keyFile  = flag.String("keyfile", "", "path to private key file")
)

func main() {
	flag.Parse()

	if *port < 0 || *port >= 1<<16 {
		fmt.Println("-port has invalid port:", *port)
		os.Exit(1)
	}
	webRootPath := path.Dir(*webRoot)
	if _, err := os.Stat(webRootPath); os.IsNotExist(err) {
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

	http.Handle("/", http.FileServer(http.Dir(webRootPath)))

	srv := &http.Server{
		Addr: fmt.Sprintf(":%d", *port),
		TLSConfig: &tls.Config{
			GetCertificate: gc,
		},
	}

	if err := srv.ListenAndServeTLS("", ""); err != nil {
		fmt.Println("Failed to listen and serve:", err)
		os.Exit(1)
	}

	fmt.Printf("pandaweb is running on port %d...\n", *port)

	for _ = range sigChan {
		log.Printf("Reloading TLS certificate")
		if err := cm.LoadX509KeyPair(*certFile, *keyFile); err != nil {
			log.Println("Failed to reload TLS certificate:", err)
		}
	}
}
