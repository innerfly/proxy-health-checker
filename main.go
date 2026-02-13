package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
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
	if _, err := conn.Read(buf); err != nil {
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
		if _, err := conn.Read(authResp); err != nil {
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
	fmt.Sscanf(port, "%d", &portNum)
	portBytes[0] = byte(portNum >> 8)
	portBytes[1] = byte(portNum & 0xFF)
	connectReq = append(connectReq, portBytes[:]...)

	if _, err := conn.Write(connectReq); err != nil {
		result.Error = fmt.Sprintf("connect error: %v", err)
		return result
	}

	connectResp := make([]byte, 4)
	if _, err := conn.Read(connectResp); err != nil {
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

	host := parsedProxy.Hostname()
	port := parsedProxy.Port()
	if port == "" {
		port = "8443"
	}

	secret := parsedProxy.User.Username()
	if secret == "" {
		result.Error = "missing secret in MTProto URL"
		return result
	}

	secretBytes, err := hex.DecodeString(secret)
	if err != nil || len(secretBytes) != 16 {
		result.Error = "invalid secret format (must be 32 hex chars)"
		return result
	}

	address := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()

	result.Healthy = true
	result.Latency = time.Since(start)
	return result
}

func checkProxy(proxyURL string, testURL string, timeout time.Duration) ProxyResult {
	if strings.HasPrefix(proxyURL, "socks5://") {
		return checkSOCKS5Proxy(proxyURL, testURL, timeout)
	} else if strings.HasPrefix(proxyURL, "mtproto://") {
		return checkMTProtoProxy(proxyURL, timeout)
	}
	return checkHTTPProxy(proxyURL, testURL, timeout)
}

func loadEnv(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentKey string
	var currentValue strings.Builder

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if line contains KEY=VALUE
		if strings.Contains(line, "=") {
			// Save previous key-value if exists
			if currentKey != "" {
				os.Setenv(currentKey, currentValue.String())
			}

			// Parse new key-value
			parts := strings.SplitN(line, "=", 2)
			currentKey = strings.TrimSpace(parts[0])
			currentValue.Reset()
			currentValue.WriteString(strings.TrimSpace(parts[1]))
		} else {
			// Continuation line (no = sign)
			if currentKey != "" {
				if currentValue.Len() > 0 {
					currentValue.WriteString(",")
				}
				currentValue.WriteString(line)
			}
		}
	}

	// Save last key-value
	if currentKey != "" {
		os.Setenv(currentKey, currentValue.String())
	}

	return scanner.Err()
}

func main() {
	// Load .env file
	if err := loadEnv(".env"); err != nil {
		fmt.Printf("Error loading .env file: %v\n", err)
		os.Exit(1)
	}

	// Get proxy list from environment variable
	proxyList := os.Getenv("PROXY_LIST")
	if proxyList == "" {
		fmt.Println("Error: PROXY_LIST environment variable is not set")
		os.Exit(1)
	}

	// Parse comma-separated proxy list
	proxies := []string{}
	for _, proxy := range strings.Split(proxyList, ",") {
		proxy = strings.TrimSpace(proxy)
		if proxy != "" {
			proxies = append(proxies, proxy)
		}
	}

	if len(proxies) == 0 {
		fmt.Println("Error: No proxies found in PROXY_LIST")
		os.Exit(1)
	}

	// Get test URL from environment variable (default: google.com)
	testURL := os.Getenv("TEST_URL")
	if testURL == "" {
		testURL = "http://www.google.com"
	}
	// Ensure URL has scheme
	if !strings.HasPrefix(testURL, "http://") && !strings.HasPrefix(testURL, "https://") {
		testURL = "http://" + testURL
	}

	timeout := 10 * time.Second

	fmt.Printf("Testing %d proxies against: %s\n", len(proxies), testURL)
	fmt.Println(strings.Repeat("-", 80))

	var wg sync.WaitGroup
	resultChan := make(chan ProxyResult, len(proxies))

	for _, proxy := range proxies {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			result := checkProxy(p, testURL, timeout)
			resultChan <- result
		}(proxy)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		fmt.Printf("%s\n", result.Proxy)
		if result.Healthy {
			fmt.Printf("  ✓ HEALTHY - Latency: %v\n", result.Latency)
		} else {
			fmt.Printf("  ✗ FAILED - Error: %s\n", result.Error)
		}
		fmt.Println()
	}
}
