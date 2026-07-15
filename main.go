package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	if err := loadEnv(".env"); err != nil {
		fmt.Printf("Error loading .env file: %v\n", err)
		os.Exit(1)
	}

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

	testURL := os.Getenv("TEST_URL")
	if testURL == "" {
		testURL = "http://www.google.com"
	}
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
			resultChan <- checkProxy(p, testURL, timeout)
		}(proxy)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		if result.Healthy {
			fmt.Printf("\033[32m✓\033[0m %s\n", string([]rune(result.Proxy)[:min(180, len([]rune(result.Proxy)))]))
			fmt.Printf("  Latency: %v\n", result.Latency)
		} else {
			fmt.Printf("\033[31m✗\033[0m %s\n", string([]rune(result.Proxy)[:min(180, len([]rune(result.Proxy)))]))
			fmt.Printf("  Error: %s\n", result.Error)
		}
	}
}
