package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ProxyResult struct {
	Proxy   string
	Healthy bool
	Error   string
	Latency time.Duration
}

func checkHTTPProxy(proxyURL string, testURL string, timeout time.Duration) ProxyResult {
	start := time.Now()
	result := ProxyResult{Proxy: proxyURL}

	parsedProxy, err := url.Parse(proxyURL)
	if err != nil {
		result.Error = fmt.Sprintf("parse error: %v", err)
		return result
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(parsedProxy),
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	resp, err := client.Get(testURL)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	result.Healthy = resp.StatusCode == 200
	result.Latency = time.Since(start)
	if !result.Healthy {
		result.Error = fmt.Sprintf("status code: %d", resp.StatusCode)
	}

	return result
}

func checkSOCKS5Proxy(proxyURL string, testURL string, timeout time.Duration) ProxyResult {
	start := time.Now()
	result := ProxyResult{Proxy: proxyURL}

	parsedProxy, err := url.Parse(proxyURL)
	if err != nil {
		result.Error = fmt.Sprintf("parse error: %v", err)
		return result
	}

	host := parsedProxy.Host
	if parsedProxy.Port() == "" {
		host = net.JoinHostPort(parsedProxy.Hostname(), "1080")
	}

	conn, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	// SOCKS5 handshake
	var auth byte = 0x00
	username := parsedProxy.User.Username()
	password, _ := parsedProxy.User.Password()

	if username != "" {
		auth = 0x02
	}

	// Send greeting
	if _, err := conn.Write([]byte{0x05, 0x01, auth}); err != nil {
		result.Error = fmt.Sprintf("handshake error: %v", err)
		return result
	}

	// Read response
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		result.Error = fmt.Sprintf("handshake response error: %v", err)
		return result
	}

	if buf[0] != 0x05 {
		result.Error = "invalid SOCKS version"
		return result
	}

	// Username/password authentication
	if buf[1] == 0x02 {
		authReq := []byte{0x01}
		authReq = append(authReq, byte(len(username)))
		authReq = append(authReq, []byte(username)...)
		authReq = append(authReq, byte(len(password)))
		authReq = append(authReq, []byte(password)...)

		if _, err := conn.Write(authReq); err != nil {
			result.Error = fmt.Sprintf("auth error: %v", err)
			return result
		}

		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			result.Error = fmt.Sprintf("auth response error: %v", err)
			return result
		}

		if authResp[1] != 0x00 {
			result.Error = "authentication failed"
			return result
		}
	} else if buf[1] != 0x00 {
		result.Error = "unsupported authentication method"
		return result
	}

	// Connect to test destination
	connectReq := []byte{0x05, 0x01, 0x00, 0x03}
	// Parse domain from test URL
	parsedTestURL, err := url.Parse(testURL)
	if err != nil {
		result.Error = fmt.Sprintf("test URL parse error: %v", err)
		return result
	}
	domain := parsedTestURL.Hostname()
	port := parsedTestURL.Port()
	if port == "" {
		if parsedTestURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	connectReq = append(connectReq, byte(len(domain)))
	connectReq = append(connectReq, []byte(domain)...)
	// Convert port string to bytes
	var portBytes [2]byte
	portNum := 80
	if _, err := fmt.Sscanf(port, "%d", &portNum); err != nil {
		result.Error = fmt.Sprintf("invalid port: %v", err)
		return result
	}
	portBytes[0] = byte(portNum >> 8)
	portBytes[1] = byte(portNum & 0xFF)
	connectReq = append(connectReq, portBytes[:]...)

	if _, err := conn.Write(connectReq); err != nil {
		result.Error = fmt.Sprintf("connect error: %v", err)
		return result
	}

	connectResp := make([]byte, 4)
	if _, err := io.ReadFull(conn, connectResp); err != nil {
		result.Error = fmt.Sprintf("connect response error: %v", err)
		return result
	}

	if connectResp[1] != 0x00 {
		result.Error = fmt.Sprintf("connection failed, code: %d", connectResp[1])
		return result
	}

	result.Healthy = true
	result.Latency = time.Since(start)
	return result
}

func checkMTProtoProxy(proxyURL string, timeout time.Duration) ProxyResult {
	start := time.Now()
	result := ProxyResult{Proxy: proxyURL}

	parsedProxy, err := url.Parse(proxyURL)
	if err != nil {
		result.Error = fmt.Sprintf("parse error: %v", err)
		return result
	}

	var host string
	port := "443"

	switch {
	case strings.HasPrefix(proxyURL, "tg://proxy"):
		query := parsedProxy.Query()
		host = query.Get("server")
		if host == "" {
			result.Error = "missing server in tg://proxy URL"
			return result
		}

		if queryPort := query.Get("port"); queryPort != "" {
			if _, err := strconv.Atoi(queryPort); err != nil {
				result.Error = "invalid port in tg://proxy URL"
				return result
			}
			port = queryPort
		}
	case strings.HasPrefix(proxyURL, "mtproto://"):
		host = parsedProxy.Hostname()
		port = parsedProxy.Port()
		if port == "" {
			port = "8443"
		}
	default:
		result.Error = "unsupported MTProto URL format"
		return result
	}

	address := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	conn.Close()

	result.Healthy = true
	result.Latency = time.Since(start)
	return result
}

func checkVLESSProxy(proxyURL string, timeout time.Duration) ProxyResult {
	start := time.Now()
	result := ProxyResult{Proxy: proxyURL}

	parsedProxy, err := url.Parse(proxyURL)
	if err != nil {
		result.Error = fmt.Sprintf("parse error: %v", err)
		return result
	}

	uuid := parsedProxy.User.Username()
	if uuid == "" {
		result.Error = "missing UUID in VLESS URL"
		return result
	}

	host := parsedProxy.Hostname()
	if host == "" {
		result.Error = "missing host in VLESS URL"
		return result
	}

	port := parsedProxy.Port()
	if port == "" {
		port = "443"
	}

	address := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()

	security := parsedProxy.Query().Get("security")
	if security == "tls" || security == "reality" {
		sni := parsedProxy.Query().Get("sni")
		if sni == "" {
			sni = host
		}

		tlsConfig := &tls.Config{
			ServerName: sni,
		}

		if security == "reality" {
			tlsConfig.InsecureSkipVerify = false
		} else {
			tlsConfig.InsecureSkipVerify = true
		}

		tlsConn := tls.Client(conn, tlsConfig)
		tlsConn.SetDeadline(time.Now().Add(timeout))
		if err := tlsConn.Handshake(); err != nil {
			result.Error = fmt.Sprintf("TLS handshake error: %v", err)
			return result
		}
		tlsConn.Close()
	}

	result.Healthy = true
	result.Latency = time.Since(start)
	return result
}

func checkProxy(proxyURL string, testURL string, timeout time.Duration) ProxyResult {
	if strings.HasPrefix(proxyURL, "socks5://") {
		return checkSOCKS5Proxy(proxyURL, testURL, timeout)
	} else if strings.HasPrefix(proxyURL, "vless://") {
		return checkVLESSProxy(proxyURL, timeout)
	} else if strings.HasPrefix(proxyURL, "mtproto://") || strings.HasPrefix(proxyURL, "tg://proxy") {
		return checkMTProtoProxy(proxyURL, timeout)
	}
	return checkHTTPProxy(proxyURL, testURL, timeout)
}
