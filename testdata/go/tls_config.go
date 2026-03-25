package main

import (
	"crypto/tls"
	"log"
	"net/http"
)

func main() {
	// TLS config with quantum-vulnerable cipher suites
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}

	server := &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
	}

	log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem"))
}
