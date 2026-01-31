# Proxy Checker

A lightweight Go tool to check the health and latency of HTTP, HTTPS, and SOCKS5 proxies.

## Features

- Supports HTTP, HTTPS, and SOCKS5 proxies
- Concurrent proxy testing
- Configurable test URL
- Authentication support (username/password)
- Latency measurement

## Usage

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Configure your proxies and test URL in `.env`:
   ```dotenv
   PROXY_LIST=
   http://username:password@proxy.example.com:80
   https://proxy.example.com:443
   socks5://proxy.example.com:1080

   TEST_URL=google.com
   ```

3. Run the checker:
   ```bash
   go run main.go
   ```

## Configuration

- `PROXY_LIST`: List of proxies to check (one per line after the first)
- `TEST_URL`: URL to test proxy connectivity (default: google.com)

## Output

The tool displays each proxy's status with either:
- ✓ HEALTHY - Latency: [time]
- ✗ FAILED - Error: [error message]
