
# HMAC File Server

**A Secure, Scalable File Handling Server with HMAC Authentication**

The HMAC File Server is a robust and secure solution for handling file uploads and downloads. It integrates HMAC authentication, multiple encryption methods, resumable transfers, deduplication, virus scanning with ClamAV, rate limiting, IP management, and comprehensive monitoring using Prometheus metrics.

---

## Key Features

- **Authentication**: HMAC-based authentication supporting multiple protocols (`v`, `v2`, `token`).
- **Encryption**: Supports AES-CTR and XOR encryption methods.
- **File Handling**:
  - Resumable uploads and downloads.
  - Deduplication using Redis.
  - File versioning with configurable version limits.
  - Chunked uploads for large files.
- **Security**:
  - Virus scanning with ClamAV integration.
  - IP rate limiting and management.
  - Fail2Ban integration for automated IP blocking.
- **Monitoring**: Prometheus metrics for real-time monitoring of performance and resource usage.
- **Graceful Shutdown**: Ensures all ongoing processes are completed before shutdown.
- **Flexible Configuration**: Extensive `config.toml` for customizing server behavior.

---

## Bug Fixes in v2.1.0-pre

- **Encryption**:
  - Improved error handling for invalid or missing AES/XOR keys.
  - Ensures fallback to unencrypted mode when configured.
- **Resumable Transfers**:
  - Addressed inconsistencies in resumable download handling.
  - Improved chunked upload performance with adaptive buffer sizes.
- **Version Cleanup Logic**:
  - Fixed unintentional deletion of versions beyond the `MaxVersions` limit.
- **ClamAV Integration**:
  - Resolved connection handling with ClamAV sockets to reduce scan delays and failures.

---

## Known Issues in v2.1.0-pre

- **Redis Failover**:
  - Redis-backed deduplication may experience brief interruptions during failover. Further improvements planned for high-availability setups.
- **ClamAV Scanning Performance**:
  - Large file scanning may exhibit latency due to single-threaded ClamAV processes. Configurable `NumScanWorkers` alleviates most delays.

---

## Configuration

### Example `config.toml`

```toml
# Server settings
ListenIP                  = "0.0.0.0"                     # IP address to bind the server to
ListenPort                = "8080"                        # Port for the file server
UnixSocket                = false                         # Use Unix sockets if true
Secret                    = "your-secret-hmac-key"        # HMAC secret for authentication
StoreDir                  = "/var/lib/hmac-files"         # Directory for storing files
UploadSubDir              = "upload"                      # Subdirectory for uploads
LoggingEnabled            = true                          # Enable logging
LogLevel                  = "info"                        # Log level: "debug", "info", "warn", "error"
LogFile                   = "/var/log/hmac.log"           # Log file path
ListenIPMetrics           = "127.0.0.1"                   # IP address to bind the Prometheus metrics
MetricsEnabled            = true                          # Enable Prometheus metrics
MetricsPort               = "9090"                        # Port for metrics server
FileTTL                   = "365d"                        # Time-to-live for files (e.g., "30d", "24h")
ResumableUploadsEnabled   = true                          # Allow resumable uploads
ResumableDownloadsEnabled = true                          # Allow resumable downloads
EnableVersioning          = false                         # Enable file versioning
MaxVersions               = 5                             # Max file versions to keep
ChunkedUploadsEnabled     = true                          # Enable chunked uploads
ChunkSize                 = 1048576                       # Chunk size in bytes (e.g., 1MB)
AllowedExtensions         = [".txt", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".avi", ".mkv", ".wav"]  # Allowed file extensions
NumWorkers                = 5                             # Number of upload workers
UploadQueueSize           = 50                            # Upload queue size
ReadTimeout               = "4800s"                       # Read timeout
WriteTimeout              = "4800s"                       # Write timeout
IdleTimeout               = "65s"                         # Idle timeout
GracefulShutdownTimeout   = 10                            # Timeout for graceful shutdown in seconds

# Encryption settings
AESEnabled                = false                         # Enable AES encryption
Method                    = "aes"                         # Encryption method: "aes", "xor"
AESKey                    = ""                            # Hex-encoded AES key (optional, derived from Secret if not set)
XORKey                    = ""                            # Hex-encoded XOR key (optional, derived from Secret if not set)
XOREnabled                = false                         # Enable XOR encryption

# TLS settings
EnableTLS                 = false                         # Enable TLS for secure connections
CertDir                   = "/etc/ssl/certs"              # Directory for certificates
Hostnames                 = ["example.com"]               # Domain names for TLS certificates
UseStaging                = false                         # Use staging certificates for testing purposes

# ClamAV settings
ClamAVEnabled             = true                          # Enable virus scanning
ClamAVSocket              = "/var/run/clamav/clamd.ctl"    # Path to ClamAV socket
NumScanWorkers            = 5                             # Number of ClamAV scan workers

# Redis settings
RedisEnabled              = true                          # Enable Redis for caching
RedisAddr                 = "localhost:6379"              # Redis address
RedisPassword             = ""                            # Redis password
RedisDBIndex              = 0                             # Redis database index
RedisHealthCheckInterval  = "30s"                         # Health check interval

# IP management
EnableIPManagement        = false                         # Enable IP-based access control
AllowedIPs                = ["0.0.0.0/0"]                 # List of allowed IPs
BlockedIPs                = []                            # List of blocked IPs
IPCheckInterval           = "60s"                         # Interval for checking and updating IP lists
IPSource                  = "header"                      # "header" or "nginx-log"
NginxLogFile              = "/var/log/nginx/access.log"   # Required if IPSource is set to "nginx-log"

# Rate limiting
EnableRateLimiting        = false                         # Enable rate limiting to prevent abuse
RequestsPerMinute         = 60                            # Maximum number of requests allowed per minute per IP
RateLimitInterval         = "1m"                          # Interval duration for rate limiting

# Fail2Ban settings
Fail2BanEnabled           = true                          # Enable Fail2Ban integration for automated IP blocking
Fail2BanCommand           = "/usr/bin/fail2ban-client"    # Command path to interact with Fail2Ban
Fail2BanJail              = "hmac-auth"                   # Name of the Fail2Ban jail to use for blocking

# Deduplication
DeduplicationEnabled      = true                          # Enable deduplication to avoid storing duplicate files
```

---

## Upgrade Instructions

1. **Backup**: Ensure all configuration files and critical data are backed up.
2. **Update Configuration**: Modify your `config.toml` file to incorporate new encryption and logging options.
3. **Restart**: Restart the file server to apply changes.

---

## Prometheus Metrics

- **System**:
  - `memory_usage_bytes`: Current memory usage in bytes.
  - `cpu_usage_percent`: Current CPU usage as a percentage.
  - `goroutines_count`: Number of active goroutines.
- **Uploads**:
  - `file_server_upload_duration_seconds`: Histogram of file upload durations.
  - `file_server_upload_errors_total`: Total number of upload errors.
  - `file_server_uploads_total`: Total successful uploads.
  - `file_server_upload_size_bytes`: Histogram of uploaded file sizes in bytes.
- **Downloads**:
  - `file_server_download_duration_seconds`: Histogram of file download durations.
  - `file_server_download_errors_total`: Total number of download errors.
  - `file_server_downloads_total`: Total successful downloads.
  - `file_server_download_size_bytes`: Histogram of downloaded file sizes in bytes.
- **Security**:
  - `infected_files_total`: Total number of infected files detected by ClamAV.
  - `file_deletions_total`: Total number of files deleted based on FileTTL.

---

## Feedback

For questions, bug reports, or suggestions, please contact our team at [support@uuxo.net](mailto:support@uuxo.net).

Thank you for your continued support in shaping the future of the HMAC File Server!
