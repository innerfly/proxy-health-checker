package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoadEnv(t *testing.T) {
	content := `TEST_URL=google.com
PROXY_LIST=
http://proxy1
http://proxy2
OTHER_KEY=value`

	tmpFile, err := os.CreateTemp("", ".env")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Clear relevant env vars
	os.Unsetenv("TEST_URL")
	os.Unsetenv("PROXY_LIST")
	os.Unsetenv("OTHER_KEY")

	if err := loadEnv(tmpFile.Name()); err != nil {
		t.Fatalf("loadEnv failed: %v", err)
	}

	if os.Getenv("TEST_URL") != "google.com" {
		t.Errorf("Expected TEST_URL=google.com, got %s", os.Getenv("TEST_URL"))
	}
	if os.Getenv("PROXY_LIST") != "http://proxy1,http://proxy2" {
		t.Errorf("Expected PROXY_LIST=http://proxy1,http://proxy2, got %s", os.Getenv("PROXY_LIST"))
	}
	if os.Getenv("OTHER_KEY") != "value" {
		t.Errorf("Expected OTHER_KEY=value, got %s", os.Getenv("OTHER_KEY"))
	}
}

func TestCheckHTTPProxy(t *testing.T) {
	// Mock proxy server
	proxyServer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "CONNECT" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	proxy := net.ListenConfig{}
	ln, err := proxy.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	go http.Serve(ln, proxyServer)

	proxyURL := "http://" + ln.Addr().String()
	testURL := "http://example.com"
	timeout := 2 * time.Second

	result := checkHTTPProxy(proxyURL, testURL, timeout)
	if !result.Healthy {
		t.Errorf("Expected healthy proxy, got error: %s", result.Error)
	}
}

func TestCheckVLESSProxy(t *testing.T) {
	timeout := 2 * time.Second

	// Test 1: Non-TLS VLESS proxy (TCP only)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	vlessURL := fmt.Sprintf("vless://07842c30-a056-4f60-a624-6a0d7ad5a4f2@%s?type=tcp&encryption=none#test", ln.Addr().String())
	result := checkVLESSProxy(vlessURL, timeout)
	if !result.Healthy {
		t.Errorf("Expected healthy VLESS proxy (TCP), got error: %s", result.Error)
	}

	// Test 2: TLS VLESS proxy with mock TLS server
	tlsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start TLS mock server: %v", err)
	}
	defer tlsLn.Close()

	go func() {
		cert, err := generateTestCert()
		if err != nil {
			return
		}
		server := &http.Server{
			Addr:    tlsLn.Addr().String(),
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		}
		server.ServeTLS(tlsLn, "", "")
	}()

	tlsURL := fmt.Sprintf("vless://07842c30-a056-4f60-a624-6a0d7ad5a4f2@%s?type=tcp&encryption=none&security=tls&sni=localhost#test", tlsLn.Addr().String())
	result = checkVLESSProxy(tlsURL, timeout)
	if !result.Healthy {
		t.Errorf("Expected healthy VLESS proxy (TLS), got error: %s", result.Error)
	}

	// Test 3: Missing UUID
	invalidURL := "vless://@127.0.0.1:443?type=tcp#test"
	result = checkVLESSProxy(invalidURL, timeout)
	if result.Healthy || !strings.Contains(result.Error, "missing UUID") {
		t.Errorf("Expected UUID error, got: %+v", result)
	}

	// Test 4: Unreachable host (connection refused)
	unreachableURL := "vless://07842c30-a056-4f60-a624-6a0d7ad5a4f2@127.0.0.1:1?type=tcp#test"
	result = checkVLESSProxy(unreachableURL, timeout)
	if result.Healthy {
		t.Error("Expected unreachable proxy to be unhealthy")
	}
}

func TestCheckMTProtoProxy(t *testing.T) {
	timeout := 2 * time.Second

	// Test 1: Valid MTProto proxy (simple obfuscation mode, no prefix)
	secretPlain := "98b8895c9b2b43d67d931cd5fed7ab79616e6465782e7275"
	secretBytesPlain, _ := hex.DecodeString(secretPlain)
	runMTProtoHandshakeTest(t, timeout, secretPlain, secretBytesPlain)

	// Test 2: Valid MTProto proxy with 0xee prefix (DC-routed mode)
	secretEE := "eed598b8895c9b2b43d67d931cd5fed7ab79616e6465782e7275"
	secretBytesEE, _ := hex.DecodeString(secretEE[4:]) // skip ee + DC
	runMTProtoHandshakeTest(t, timeout, secretEE, secretBytesEE)

	// Test 3: Invalid handshake response (server sends garbage)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				frame := make([]byte, 64)
				if _, err := io.ReadFull(c, frame); err != nil {
					return
				}
				c.Write([]byte("garbage response"))
			}(conn)
		}
	}()

	badURL := fmt.Sprintf("tg://proxy?server=127.0.0.1&port=%d&secret=eed598b8895c9b2b43d67d931cd5fed7", ln.Addr().(*net.TCPAddr).Port)
	result := checkMTProtoProxy(badURL, timeout)
	if result.Healthy {
		t.Error("Expected unhealthy proxy for invalid handshake response")
	}

	// Test 4: Unreachable host
	unreachableURL := "tg://proxy?server=127.0.0.1&port=1&secret=eed598b8895c9b2b43d67d931cd5fed7"
	result = checkMTProtoProxy(unreachableURL, timeout)
	if result.Healthy {
		t.Error("Expected unreachable proxy to be unhealthy")
	}
}

func runMTProtoHandshakeTest(t *testing.T, timeout time.Duration, secretHex string, secretBytes []byte) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(timeout))

				frame := make([]byte, 64)
				if _, err := io.ReadFull(c, frame); err != nil {
					return
				}

				nonce := make([]byte, 4)
				copy(nonce, frame[4:8])

				for i := 8; i < 64; i++ {
					frame[i] ^= secretBytes[(i-8)%len(secretBytes)]
				}

				response := make([]byte, 64)
				if _, err := rand.Read(response); err != nil {
					return
				}
				copy(response[0:4], nonce)

				for i := 8; i < 64; i++ {
					response[i] ^= secretBytes[(i-8)%len(secretBytes)]
				}

				c.Write(response)
			}(conn)
		}
	}()

	mtprotoURL := fmt.Sprintf("tg://proxy?server=127.0.0.1&port=%d&secret=%s", ln.Addr().(*net.TCPAddr).Port, secretHex)
	result := checkMTProtoProxy(mtprotoURL, timeout)
	if !result.Healthy {
		t.Errorf("Expected healthy MTProto proxy (secret=%s), got error: %s", secretHex, result.Error)
	}
}

func generateTestCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}
