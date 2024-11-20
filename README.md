
# HMAC File Server

**A Secure, Scalable File Handling Server with HMAC Authentication**

The HMAC File Server is a secure solution for file uploads and downloads. It features HMAC authentication, AES encryption, resumable transfers, deduplication, and monitoring with Prometheus metrics.

---

## Key Features

- **Authentication**: HMAC-based authentication with multiple protocols (`v`, `v2`, `token`).
- **File Handling**: Resumable uploads/downloads, deduplication, and file versioning.
- **Security**: AES encryption, ClamAV virus scanning, IP rate limiting, and Fail2Ban integration.
- **Monitoring**: Prometheus metrics to monitor performance and resource usage.

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Prometheus Metrics](#prometheus-metrics)
- [Development](#development)
- [Known Limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)

---

## Requirements

1. **Software**:
   - Go 1.20+
   - Redis (optional, for deduplication and token storage)
   - ClamAV (optional, for virus scanning)

2. **Environment**:
   - Adequate storage space for file storage and logs
   - Network configuration for IP management (optional)

---

## Installation

### Clone the Repository

```bash
git clone https://github.com/your-username/hmac-file-server.git
cd hmac-file-server
```

### Build the Application

```bash
go build -o hmac-file-server main.go
```

### Run the Server

```bash
./hmac-file-server
```

---

## Configuration

### Example `config.toml`

```toml
# Server settings
ListenIP                  = "0.0.0.0"                 # IP address to bind the server to
ListenPort                = "8080"                    # Port for the file server
UnixSocket                = false                     # Use Unix sockets if true
Secret                    = "your-secret-hmac-key"    # HMAC secret for authentication
StoreDir                  = "/var/lib/hmac-files"     # Directory for storing files
UploadSubDir              = "upload"                  # Subdirectory for uploads
LoggingEnabled            = true
LogLevel                  = "info"                    # Log level: "debug", "info", "warn", "error"
LogFile                   = "/var/log/hmac.log"       # Log file path
ListenIPMetrics           = "127.0.0.1"               # IP address to bind the prometheus metrics
MetricsEnabled            = true                      # Enable Prometheus metrics
MetricsPort               = "9090"                   # Port for metrics server
FileTTL                   = "365d"                    # Time-to-live for files (e.g., "30d", "24h")
ResumableUploadsEnabled   = true                      # Allow resumable uploads
ResumableDownloadsEnabled = true                      # Allow resumable downloads
EnableVersioning          = false                     # Enable file versioning
MaxVersions               = 5                         # Max file versions to keep
ChunkedUploadsEnabled     = true                      # Enable chunked uploads
ChunkSize                 = 1048576                   # Chunk size in bytes (e.g., 1MB)
AllowedExtensions         = [".txt", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".avi", ".mkv", ".wav"]
NumWorkers                = 5                         # Number of upload workers
UploadQueueSize           = 50                        # Upload queue size
ReadTimeout               = "4800s"                   # Read timeout
WriteTimeout              = "4800s"                   # Write timeout
IdleTimeout               = "65s"                     # Idle timeout
GracefulShutdownTimeout   = 10                        # Timeout for graceful shutdown in seconds

# Encryption settings
AESEnabled                = false                     # Enable AES encryption
Method                    = "aes"                     # Encryption method: "hmac" or "aes"

# TLS settings
EnableTLS                 = false                     # Enable TLS
CertDir                   = "/etc/ssl/certs"          # Directory for certificates
Hostnames                 = ["example.com"]           # Domain names
UseStaging                = false                     # Use staging certificates

# ClamAV settings
ClamAVEnabled             = true                      # Enable virus scanning
ClamAVSocket              = "/var/run/clamav/clamd.ctl" # Path to ClamAV socket
NumScanWorkers            = 5                         # Number of ClamAV scan workers

# Redis settings
RedisEnabled              = true                      # Enable Redis for caching
RedisAddr                 = "localhost:6379"          # Redis address
RedisPassword             = ""                        # Redis password
RedisDBIndex              = 0                         # Redis database index
RedisHealthCheckInterval  = "30s"                     # Health check interval

# IP management
EnableIPManagement        = false                     # Enable IP management
AllowedIPs                = ["0.0.0.0/0"]             # List of allowed IPs
BlockedIPs                = []                        # List of blocked IPs
IPCheckInterval           = "60s"                     # Interval for IP checks
IPSource                  = "header"                  # "header" or "nginx-log"
NginxLogFile              = "/var/log/nginx/access.log" # Required if IPSource is "nginx-log"

# Rate limiting
EnableRateLimiting        = false                     # Enable rate limiting
RequestsPerMinute         = 60                        # Max requests per minute
RateLimitInterval         = "1m"                      # Rate limit interval

# Fail2Ban settings
Fail2BanEnabled           = true                      # Enable Fail2Ban
Fail2BanCommand           = "/usr/bin/fail2ban-client" # Fail2Ban command
Fail2BanJail              = "hmac-auth"               # Fail2Ban jail name

# Deduplication
DeduplicationEnabled      = true                      # Enable deduplication
```

---

## Usage Examples

### Upload File

```bash
# Generate HMAC for protocol version 'v'
CONTENT_LENGTH=$(stat -c%s "myfile.txt")
HMAC=$(printf "/upload/myfile.txt %d" "$CONTENT_LENGTH" | openssl dgst -sha256 -hmac "your-secret-hmac-key" | awk '{print $2}')
curl -X PUT "http://localhost:8080/upload/myfile.txt?v=$HMAC" --data-binary @myfile.txt
```

### Download File

```bash
curl -X GET "http://localhost:8080/upload/myfile.txt"
```

---

## Prometheus Metrics

- **System**:
  - `memory_usage_bytes`: Current memory usage.
  - `cpu_usage_percent`: Current CPU usage.
  - `goroutines_count`: Number of active goroutines.

- **Uploads**:
  - `file_server_upload_duration_seconds`: Upload duration histogram.
  - `file_server_upload_errors_total`: Total upload errors.
  - `file_server_uploads_total`: Total successful uploads.
  - `file_server_upload_size_bytes`: Uploaded file size histogram.

- **Downloads**:
  - `file_server_download_duration_seconds`: Download duration histogram.
  - `file_server_download_errors_total`: Total download errors.
  - `file_server_downloads_total`: Total successful downloads.
  - `file_server_download_size_bytes`: Downloaded file size histogram.

- **Security**:
  - `infected_files_total`: Total number of infected files detected.
  - `file_deletions_total`: Total number of files deleted based on FileTTL.

---

## Development

### Running Tests

```bash
go test ./...
```

### Dependency Management

```bash
go mod tidy
```

---

## Known Limitations

- **Integrity Protection**: AES-CTR encrypts data but doesn't prevent tampering. Use HMAC for integrity.
- **Redis Performance**: Redis performance may degrade under heavy workloads. Ensure proper configuration and resources.
- **Fail2Ban Integration**: Ensure that Fail2Ban is correctly configured on your system to work with the provided commands.

---

## Contributing

Contributions are welcome! Submit issues, suggestions, or pull requests.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
