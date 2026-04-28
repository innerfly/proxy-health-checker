# Proxy Checker

A lightweight Go tool to check the health and latency of HTTP, HTTPS, SOCKS5, MTProto, and VLESS proxies.

## Features

- Supports HTTP, HTTPS, SOCKS5, MTProto, and VLESS proxies
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
   tg://proxy?server=tg.example.com&port=443&secret=eed598b8895c9b2b43d67d931cd5fed7ab79616e6465782e7275
   vless://07842c30-a056-4f60-a624-6a0d7ad5a4f2@vpn.example.com:443?type=tcp&encryption=none&security=reality&pbk=9OoQlQq62iGD33uJ9Q4_FY4chLxK1tQp43bGKDDFHlM&fp=chrome&sni=dzen.ru&sid=c8c8022a&spx=%2F#vless

   TEST_URL=google.com
   ```

3. Run the checker:
   ```bash
   go run main.go
   ```

## Configuration

- `PROXY_LIST`: List of proxies to check (one per line after the first)
- `TEST_URL`: URL to test proxy connectivity (default: google.com)

### MTProto format

Use Telegram MTProto proxy links in this format:

```text
tg://proxy?server=tg.example.com&port=443&secret=eed598b8895c9b2b43d67d931cd5fed7ab79616e6465782e7275
```

Required query parameters:
- `server`: MTProto proxy hostname
- `secret`: hex-encoded MTProto secret

Optional query parameters:
- `port`: MTProto proxy port, defaults to `443`

### VLESS format

Use VLESS proxy links in this format:

```text
vless://<uuid>@<host>:<port>?type=<type>&encryption=<encryption>&security=<security>&pbk=<public_key>&fp=<fingerprint>&sni=<sni>&sid=<short_id>&spx=<spoofed_host>#<name>
```

Required components:
- `uuid`: VLESS user ID (UUID format)
- `host`: VLESS proxy hostname
- `port`: VLESS proxy port (defaults to 443 if not specified)

Optional query parameters:
- `type`: Transport type (tcp, ws, grpc, etc.)
- `encryption`: Encryption method (none, etc.)
- `security`: Security layer (none, tls, reality)
- `pbk`: Public key for TLS/Reality
- `fp`: Fingerprint for TLS
- `sni`: Server name indication for TLS
- `sid`: Short ID for Reality
- `spx`: Spoofed host header
- `#name`: Optional name/remark for the proxy

## Output

The tool displays each proxy's status with either:
- ✓ HEALTHY - Latency: [time]
- ✗ FAILED - Error: [error message]
