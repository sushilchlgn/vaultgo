package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"
)

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080": true,
		"localhost:8080": true,
		"[::1]:8080":     true,
		"0.0.0.0:8080":   false,
		":8080":          false,
		"192.168.1.5:80": false,
		"example.com:80": false,
		"not-an-address": false,
	}
	for addr, want := range cases {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestGeneratedCertIsUsable(t *testing.T) {
	certPath, keyPath, err := generateSelfSignedCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// The server must be able to load the pair.
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("certificate and key do not match: %v", err)
	}

	// A client that trusts this certificate must accept it for localhost.
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("could not parse the generated certificate")
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "localhost"}); err != nil {
		t.Errorf("should verify for localhost: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "evil.example.com"}); err == nil {
		t.Error("must NOT verify for an unrelated hostname")
	}
}