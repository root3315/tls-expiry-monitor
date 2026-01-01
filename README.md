# TLS Expiry Monitor

A command-line tool to monitor TLS certificate expiry dates and send alerts. Built in Go with zero external dependencies.

## Description

TLS Expiry Monitor is a lightweight CLI utility that checks SSL/TLS certificates for specified domains and alerts you before they expire. It's designed for:

- **DevOps teams** monitoring production certificate health
- **System administrators** managing multiple domains
- **CI/CD pipelines** validating certificate status before deployments
- **Monitoring systems** integrating certificate checks into alerting workflows

## Features

- Check multiple domains in parallel
- Configurable warning and critical thresholds
- Human-readable and JSON output formats
- Color-coded terminal output
- Environment variable configuration
- Support for custom ports
- Concurrent certificate checking for fast execution
- Exit codes for scripting integration

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/tls-expiry-monitor/tls-expiry-monitor.git
cd tls-expiry-monitor

# Build the binary
go build -o tls-expiry-monitor ./cmd/tls-expiry-monitor

# Install globally
go install ./cmd/tls-expiry-monitor
```

### Using Go Install

```bash
go install github.com/tls-expiry-monitor/cmd/tls-expiry-monitor@latest
```

### Manual Download

Download the pre-built binary from the [releases page](https://github.com/tls-expiry-monitor/tls-expiry-monitor/releases) and add it to your PATH.

## Usage

### Basic Usage

```bash
# Check a single domain
tls-expiry-monitor -domains example.com

# Check multiple domains
tls-expiry-monitor -domains example.com,api.example.com,web.example.org

# Check domain with custom port
tls-expiry-monitor -domains example.com:8443
```

### Custom Thresholds

```bash
# Warn 45 days before expiry, critical at 14 days
tls-expiry-monitor -domains example.com -warning-days 45 -critical-days 14

# Aggressive monitoring (warn at 60 days, critical at 30)
tls-expiry-monitor -domains example.com -warning-days 60 -critical-days 30
```

### Output Formats

```bash
# JSON output for programmatic processing
tls-expiry-monitor -domains example.com -json

# Quiet mode (only show warnings and errors)
tls-expiry-monitor -domains example.com -quiet

# Disable colored output
tls-expiry-monitor -domains example.com -no-color
```

### Network Configuration

```bash
# Custom timeout for slow networks
tls-expiry-monitor -domains example.com -timeout 30s

# Quick check with short timeout
tls-expiry-monitor -domains example.com -timeout 5s
```

## Environment Variables

Configure the tool using environment variables instead of command-line flags:

```bash
# Domains to check (comma-separated)
export TLS_DOMAINS=example.com,api.example.com

# Alert thresholds (in days)
export TLS_WARNING_DAYS=30
export TLS_CRITICAL_DAYS=7

# Network timeout (in seconds)
export TLS_TIMEOUT=10

# Output options
export TLS_JSON=true
export TLS_QUIET=true

# Run with environment configuration
tls-expiry-monitor
```

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     tls-expiry-monitor                       │
├─────────────────────────────────────────────────────────────┤
│  main.go                                                    │
│  └── Parses CLI flags and environment variables             │
│      └── Validates configuration                            │
│          └── Executes certificate checks                    │
├─────────────────────────────────────────────────────────────┤
│  internal/config/                                           │
│  └── Configuration structure and validation                 │
│      └── Alert level determination                          │
├─────────────────────────────────────────────────────────────┤
│  internal/checker/                                          │
│  └── TLS handshake and certificate extraction               │
│      └── Concurrent domain checking                         │
├─────────────────────────────────────────────────────────────┤
│  internal/alert/                                            │
│  └── Alert formatting (text/JSON)                           │
│      └── Summary generation                                 │
│          └── Recommendations output                         │
└─────────────────────────────────────────────────────────────┘
```

### Certificate Check Process

1. **DNS Resolution**: Resolve the domain hostname to an IP address
2. **TCP Connection**: Establish a TCP connection to the specified port (default: 443)
3. **TLS Handshake**: Perform TLS handshake with `InsecureSkipVerify` enabled
4. **Certificate Extraction**: Extract the leaf certificate from the chain
5. **Expiry Calculation**: Calculate days remaining until `NotAfter` date
6. **Alert Level**: Determine alert level based on configured thresholds
7. **Output**: Format and display results

### Alert Levels

| Level | Condition | Color |
|-------|-----------|-------|
| INFO | Certificate valid > warning threshold | Green |
| WARNING | Certificate expires within warning threshold | Yellow |
| CRITICAL | Certificate expires within critical threshold | Red |
| EXPIRED | Certificate has already expired | Magenta |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All certificates healthy |
| 1 | Warning: certificates expiring soon |
| 2 | Critical: certificates expired or expiring very soon |
| 3 | Configuration or runtime error |

## Examples

### Cron Job for Daily Checks

```bash
# Add to crontab for daily 9 AM checks
0 9 * * * /usr/local/bin/tls-expiry-monitor -domains example.com,api.example.com -quiet >> /var/log/cert-check.log 2>&1
```

### CI/CD Pipeline Integration

```yaml
# GitHub Actions example
- name: Check TLS Certificates
  run: |
    go run ./cmd/tls-expiry-monitor \
      -domains ${{ vars.PROD_DOMAINS }} \
      -warning-days 30 \
      -critical-days 7 \
      -json > cert-status.json
    
    # Fail if any certificates are critical or expired
    if jq -e '.alerts[] | select(.level == "CRITICAL" or .level == "EXPIRED")' cert-status.json; then
      echo "Critical certificate issues detected!"
      exit 1
    fi
```

### Docker Container

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o tls-expiry-monitor ./cmd/tls-expiry-monitor

FROM alpine:latest
COPY --from=builder /app/tls-expiry-monitor /usr/local/bin/
ENV TLS_DOMAINS=example.com
CMD ["tls-expiry-monitor", "-quiet"]
```

### Monitoring Integration (Prometheus)

```bash
# Export metrics in a format suitable for prometheus pushgateway
tls-expiry-monitor -domains example.com -json | jq -r '
  .alerts[] | 
  "tls_cert_expiry_days{domain=\"\(.domain)\"} \(.days_until_expiry)"
'
```

## Project Structure

```
tls-expiry-monitor/
├── cmd/
│   └── tls-expiry-monitor/
│       └── main.go          # Application entry point
├── internal/
│   ├── config/
│   │   └── config.go        # Configuration management
│   ├── checker/
│   │   └── checker.go       # Certificate checking logic
│   └── alert/
│       └── alert.go         # Alert formatting and output
├── tests/
│   └── checker_test.go      # Unit tests
├── go.mod                   # Go module definition
├── go.sum                   # Dependencies checksum
└── README.md                # This file
```

## Running Tests

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./...

# Run with coverage
go test -cover ./...

# Run specific test package
go test ./tests/...
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Troubleshooting

### Connection Timeout

If you're experiencing timeouts, increase the timeout value:

```bash
tls-expiry-monitor -domains example.com -timeout 30s
```

### Self-Signed Certificates

The tool uses `InsecureSkipVerify` by default, so self-signed certificates are checked normally.

### Firewall Issues

Ensure outbound TCP connections to port 443 (or your specified port) are allowed.

### Certificate Chain Issues

To debug certificate chain problems:

```bash
# Use openssl to see full chain
openssl s_client -connect example.com:443 -showcerts
```
