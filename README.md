
# HMAC File Server

**Version: 2.0.0**

The HMAC File Server is a secure and efficient file upload and download server that uses HMAC for authentication. It supports chunked uploads, rate limiting, and integrates with Redis or a fallback database (PostgreSQL/MySQL). The server is also instrumented for monitoring with Prometheus.

---

## Table of Contents

1. [Changes from Version 1.0.0 to 2.0.0](#changes-from-version-100-to-200)
2. [Building the Code](#building-the-code)
3. [Configuration](#configuration)
4. [Logging](#logging)
5. [Prometheus Exporter](#prometheus-exporter)
6. [Systemd Integration](#systemd-integration)
7. [Upload and Download Process](#upload-and-download-process)

---

## Changes from Version 1.0.0 to 2.0.0

### New Features:
- **Dynamic Worker Management**: Added support for automatic detection of CPU cores to dynamically allocate worker goroutines (`MaxWorkers = "auto"`).
- **Prometheus Metrics**: Added comprehensive Prometheus metrics, including upload/download duration, error counters, memory usage, and active connections.
- **Graceful Shutdown**: Integrated support for graceful shutdowns with a configurable timeout (`GracefulShutdownTimeout`).
- **Rate Limiting**: Configurable upload speed limit via `MaxBytesPerSecond`.
- **Download Process**: Added HMAC-based authentication to downloads, including Prometheus tracking for download performance.
- **Fallback Database Support**: If Redis is unavailable, fallback to PostgreSQL or MySQL is now supported.

### Breaking Changes:
- **Configuration File**: The `config.toml` format has changed to include new fields (see [Configuration](#configuration)).
- **Logging**: Enhanced logging format with timestamps and levels. Log files can be rotated using external tools like `logrotate`.

---

## Building the Code

You can build the HMAC File Server from source by following these steps:

### Prerequisites:
- Go (version 1.16 or later)
- A supported database (optional): PostgreSQL, MySQL, or Redis

### Clone the Repository:
```bash
git clone https://github.com/PlusOne/hmac-file-server.git
cd hmac-file-server
```

### Build the Code:
```bash
go build -o hmac-file-server .
```

This will generate an executable called `hmac-file-server`.

---

## Configuration

The server uses a `config.toml` file for configuration. Below is an example configuration file with descriptions for each parameter.

### `config.toml` Example:

```toml
# HMAC File Server Configuration

# Listening port and socket options
ListenPort = ":8080"  # Port for the file server to listen on
UnixSocket = false  # Use Unix sockets if true, otherwise TCP

# Security configurations
Secret = "stellar-wisdom-orbit-echo"  # HMAC secret for securing uploads

# Directories for file storage
StoreDir = "/mnt/storage/hmac-file-server/"  # Directory for storing uploaded files
UploadSubDir = "upload"  # Subdirectory for uploads

# Logging configurations
LogLevel = "info"  # Logging level: "debug", "info", "warn", "error"
LogFile = "/var/log/hmac-file-server.log"  # Log file path

# Retry settings for uploads
MaxRetries = 5  # Maximum number of retries for failed uploads
RetryDelay = 2  # Delay in seconds between retries

# Metrics configuration (Prometheus)
MetricsEnabled = true  # Enable Prometheus metrics
MetricsPort = ":9090"  # Port for Prometheus metrics server

# File upload configurations
ChunkSize = 65536  # Size of each chunk for chunked uploads (in bytes)
UploadMaxSize = 1073741824  # Maximum upload size (1 GB in bytes)
MaxBytesPerSecond = 8388608  # Throttle upload speed to 1 MB/s

# Redis configuration (optional)
RedisAddr = "localhost:6379"  # Redis server address (leave blank if not using Redis)
RedisPassword = ""  # Redis password (leave blank if no password is required)
RedisDB = 0  # Redis database number

# Fallback database configuration (optional)
FallbackEnabled = false  # Enable fallback to a database if Redis is unavailable
FallbackDBType = "postgres"  # Fallback database type ("postgres" or "mysql")
FallbackDBHost = "localhost"  # Fallback database host
FallbackDBUser = "your_db_user"  # Fallback database username
FallbackDBPassword = "your_db_password"  # Fallback database password
FallbackDBName = "your_db_name"  # Fallback database name

# Graceful shutdown configuration
GracefulShutdownTimeout = 30  # Timeout for graceful shutdowns (in seconds)

# Resource management (CPU and memory)
MaxWorkers = "auto"  # Number of worker goroutines ("auto" for automatic detection)
MaxMemoryMB = 4096  # Maximum memory usage (4 GB)
```

---

## Logging

The server uses structured logging with timestamps and log levels. You can configure the log file location and the log level via the `config.toml`.

- **Log Levels**: `debug`, `info`, `warn`, `error`
- **Log File**: The log file can be configured in the `config.toml`. You can also use log rotation tools like `logrotate` to manage log files.

### Example Log Output:

```
INFO[2024-10-23T12:34:56Z] Starting HMAC File Server - v2.0
INFO[2024-10-23T12:34:56Z] Listening on :8080
INFO[2024-10-23T12:35:01Z] Incoming request: GET /upload/file1.txt
INFO[2024-10-23T12:35:02Z] Upload completed: file1.txt in 1.2s
```

---

## Prometheus Exporter

The HMAC File Server exports several key metrics via Prometheus. You can access these metrics by enabling `MetricsEnabled` in the configuration file and pointing Prometheus to the specified `MetricsPort`.

### Metrics Exported:

- `hmac_file_server_upload_duration_seconds`: Duration of file uploads
- `hmac_file_server_upload_errors_total`: Total number of upload errors
- `hmac_file_server_uploads_total`: Total successful uploads
- `hmac_file_server_download_duration_seconds`: Duration of file downloads
- `hmac_file_server_download_errors_total`: Total number of download errors
- `hmac_file_server_downloads_total`: Total successful downloads
- `memory_usage_bytes`: Current memory usage in bytes
- `cpu_usage_percent`: Current CPU usage as a percentage
- `active_connections_total`: Total number of active connections
- `goroutines_count`: Number of active goroutines
- `http_requests_total`: Total number of HTTP requests, labeled by method and path

### Example Prometheus Configuration:

```yaml
scrape_configs:
  - job_name: 'hmac_file_server'
    static_configs:
      - targets: ['localhost:9090']
```

---

## Systemd Integration

To run the HMAC File Server as a systemd service, create a unit file as shown below.

### Example Systemd Service:

```ini
[Unit]
Description=HMAC File Server
After=network.target

[Service]
ExecStart=/path/to/hmac-file-server -config /path/to/config.toml
Restart=on-failure
LimitNOFILE=4096
TimeoutStopSec=30
KillMode=process
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Steps to Install:

1. Create the service file:
   ```bash
   sudo nano /etc/systemd/system/hmac-file-server.service
   ```

2. Reload systemd and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl start hmac-file-server
   sudo systemctl enable hmac-file-server
   ```

3. Check the status:
   ```bash
   sudo systemctl status hmac-file-server
   ```

---

## Upload and Download Process

### Upload Process:
1. **Client Request**: The client sends a `PUT` request to the server with the file to upload, including an HMAC token for validation.
2. **HMAC Validation**: The server validates the HMAC token using the secret provided in the configuration. If the HMAC is valid, the upload is accepted.
3. **Chunked Uploads**: If the file is large, it can be uploaded in chunks. The server ensures the chunks are appended in the correct order.
4. **Finalization**: Once all chunks are uploaded, the server combines the file and stores it in the specified directory.

### Download Process:
1. **Client Request**: The client sends a `GET` request to download a file.
2. **HMAC Validation**: The server validates the request using an HMAC token to ensure the client is authorized to download the file.
3. **File Serving**: The file is served with proper headers for caching and content-type, and the download is tracked using Prometheus metrics.
