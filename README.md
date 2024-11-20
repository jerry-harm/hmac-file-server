
# HMAC File Server

**A Secure, Scalable File Handling Server with HMAC Authentication**

The HMAC File Server is a secure solution for file uploads and downloads. It features HMAC authentication, AES encryption, resumable transfers, deduplication, and monitoring with Prometheus metrics.

---

## Key Features

- **Authentication**: HMAC-based authentication with multiple protocols (`v`, `v2`, `token`).
- **File Handling**: Resumable uploads/downloads, deduplication, and file versioning.
- **Security**: AES encryption, ClamAV virus scanning, and IP rate limiting.
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
   - Redis (optional, for deduplication and token storage).
   - ClamAV (optional, for virus scanning).

2. **Environment**:
   - Adequate storage space for file storage and logs.
   - Network configuration for IP management (optional).

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
ListenPort               = ":8080"                  # Port for the file server
UnixSocket               = false                    # Use Unix sockets if true
Secret                   = "your-secret-hmac-key"   # HMAC secret for authentication
StoreDir                 = "/var/lib/hmac-files"    # Directory for storing files
UploadSubDir             = "upload"                # Subdirectory for uploads
LoggingEnabled           = true
LogLevel                 = "info"                  # Log level: "debug", "info", "warn", "error"
LogFile                  = "/var/log/hmac.log"     # Log file path
MetricsEnabled           = true                    # Enable Prometheus metrics
MetricsPort              = ":9090"                 # Port for metrics server

# Encryption settings
Method                   = "hmac"                  # Encryption method: "hmac" or "aes"
AESEnabled               = false
AESKey                   = "32-character-secret-key-for-aes"

# TLS settings
EnableTLS                = false                   # Enable TLS
CertDir                  = "/etc/ssl/certs"        # Directory for certificates
Hostnames                = ["example.com"]         # Domain names
UseStaging               = false                   # Use staging certificates

# Upload/download settings
ResumableUploadsEnabled  = true                    # Allow resumable uploads
ResumableDownloads       = true                    # Allow resumable downloads
ChunkedUploadsEnabled    = true                    # Enable chunked uploads
ChunkSize                = 8192                   # Chunk size in bytes
MaxVersions              = 1                       # Max file versions to keep
EnableVersioning         = false                   # Enable file versioning
FileTTL                  = "365d"                  # Time-to-live for files

# Worker and connection settings
NumWorkers               = 5                       # Number of workers
UploadQueueSize          = 50                      # Upload queue size
ReadTimeout              = "4800s"                 # Read timeout
WriteTimeout             = "4800s"                 # Write timeout
IdleTimeout              = "65s"                   # Idle timeout

# Deduplication
DeduplicationEnabled     = true                    # Enable deduplication

# Redis settings
RedisEnabled             = true                    # Enable Redis for caching
RedisAddr                = "localhost:6379"        # Redis address
RedisPassword            = ""                      # Redis password
RedisDBIndex             = 0                       # Redis database index
RedisHealthCheckInterval = "120s"                  # Health check interval

# ClamAV settings
ClamAVEnabled            = true                    # Enable virus scanning
NumScanWorkers           = 5                       # Number of ClamAV workers
ClamAVSocket             = "/var/run/clamav/clamd.ctl" # Path to ClamAV socket

# IP management
EnableIPManagement       = false                   # Enable IP management
AllowedIPs               = ["0.0.0.0/0"]           # List of allowed IPs
IPCheckInterval          = "65s"                   # Interval for IP checks

# Rate limiting
RateLimitingEnabled      = false                   # Enable rate limiting
MaxRequestsPerMinute     = 60                      # Max requests per minute
RateLimitInterval        = "1m"                    # Rate limit interval

# Fail2Ban settings
Enable                   = true                    # Enable Fail2Ban
Jail                     = "hmac-auth"             # Fail2Ban jail name
BlockCommand             = "/usr/bin/fail2ban-client set hmac-auth <IP>"
UnblockCommand           = "/usr/bin/fail2ban-client set hmac-auth unban <IP>"
MaxRetries               = 3                       # Max retries before banning
BanTime                  = "3600s"                 # Ban time in seconds

# Allowed file extensions
AllowedExtensions = [
    ".txt", ".pdf", ".jpg", ".jpeg", ".png", ".gif",
    ".mp3", ".mp4", ".avi", ".mkv", ".wav"
]
```

---

## Usage Examples

### Upload File

```bash
curl -X PUT "http://localhost:8080/upload/myfile.txt?hmac=<HMAC>" --data-binary @myfile.txt
```

### Download File

```bash
curl -X GET "http://localhost:8080/upload/myfile.txt?hmac=<HMAC>"
```

---

## Prometheus Metrics

- **System**: CPU, memory, and goroutine count.
- **Uploads**: Duration, errors, and success metrics.
- **Downloads**: Duration and success metrics.
- **Errors**: Tracks upload/download errors.

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
- **Heavy Redis Use**: Redis performance may degrade under heavy workloads.

---

## Contributing

Contributions are welcome! Submit issues, suggestions, or pull requests.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
