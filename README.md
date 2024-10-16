
# HMAC File Server - Secure File Handling Server

### Version 1.0.3

#### Overview

The **HMAC File Server** is a lightweight, highly configurable HTTP-based file server that enables secure file uploads and downloads with support for HMAC (Hash-based Message Authentication Code) for secure validation. It also includes robust rate-limiting, logging, monitoring with Prometheus metrics, and now supports **resumable uploads** for greater flexibility.

### What's New in Version 1.0.3

- **Resumable Uploads**: Supports resuming file uploads from where they left off using the `Range` HTTP header.
- **Queue-based Upload Processing**: Incoming upload requests are managed in a queue to handle concurrent uploads efficiently.
- **Detailed Logging**: Improved logging for file uploads, resumable uploads, and file serving.
- **Prometheus Metrics**: Enhanced metrics tracking for uploads, downloads, and server performance.

### Features

- **HMAC Validation**: Ensures that only authorized clients can upload or download files.
- **Resumable Uploads**: Clients can now resume large file uploads by specifying a byte offset using the `Range` header.
- **Queue-based Processing**: Uploads are managed with a queue to optimize resource use and prevent overload.
- **Auto-ban Mechanism**: Clients making too many invalid requests can be automatically banned for a configurable period.
- **Prometheus Integration**: Built-in metrics collection for monitoring server performance.
- **Multi-core Support**: Configurable to utilize multiple CPU cores for improved concurrency and performance.
- **Rate Limiting**: Throttles excessive requests to protect the server from abuse.
- **Cross-Origin Resource Sharing (CORS)**: CORS support is included for flexible integration with web-based clients.

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourrepo/hmac-file-server.git
   ```

2. Build the binary:

   ```bash
   cd hmac-file-server
   go build -o hmac-file-server
   ```

3. Prepare the `config.toml` configuration file (an example is provided).

4. Run the server:

   ```bash
   ./hmac-file-server -config ./config.toml
   ```

### Configuration (config.toml)

```toml
# Server settings
ListenPort = ":8080"            # Port for the HTTP server
UnixSocket = false              # Use Unix socket (true/false)
UnixSocketPath = ""             # Path to Unix socket (only if UnixSocket is true)

# HMAC secret for file uploads/downloads
Secret = "your-hmac-secret"     # HMAC key for securing requests

# File handling
StoreDir = "/mnt/storage/hmac-file-server"   # Directory for storing uploaded files
UploadSubDir = "upload"                      # Subdirectory for uploads

# Logging and system settings
LogLevel = "info"               # Logging level (debug, info, warn, error)
NumCores = "auto"               # Number of CPU cores to use (auto or specify number)

# Retry and blocking settings
MaxRetries = 5                  # Maximum number of retries for failed requests
RetryDelay = 2                  # Delay between retries (in seconds)
BlockAfterFails = 5             # Block client after these many failures
BlockDuration = 300             # Duration of the block (in seconds)

# Auto-unban feature
AutoUnban = true                # Automatically unban clients after block duration
AutoBanTime = 600               # Ban duration (in seconds)

# Metrics
MetricsEnabled = true           # Enable Prometheus metrics
MetricsPort = ":9090"           # Port for Prometheus metrics server

# Resumable upload settings
DeleteFiles = false             # Delete files after a set period
DeleteFilesAfterPeriod = "48h"  # Time after which files are deleted (if enabled)
```

### Usage

#### Uploading Files

To upload a file, send a `PUT` request to the `/upload/<file-path>` endpoint:

```bash
curl -X PUT -T /path/to/file http://server-address:8080/upload/<file-path>      -H "Authorization: HMAC <your-auth-token>"
```

#### Resumable Uploads

To resume an upload, specify the `Range` header to indicate the byte offset:

```bash
curl -X PUT -T /path/to/file http://server-address:8080/upload/<file-path>      -H "Authorization: HMAC <your-auth-token>"      -H "Range: bytes=1024-"
```

This will append the data starting from byte 1024.

#### Downloading Files

To download a file, send a `GET` request to the `/upload/<file-path>` endpoint:

```bash
curl -X GET http://server-address:8080/upload/<file-path>      -H "Authorization: HMAC <your-auth-token>"
```

#### Monitoring

The server exposes Prometheus metrics on the `/metrics` endpoint:

```bash
curl http://server-address:9090/metrics
```

Metrics include:
- `hmac_file_server_total_uploads`: Total number of file uploads.
- `hmac_file_server_total_downloads`: Total number of file downloads.
- `hmac_file_server_upload_duration_seconds`: Histogram of upload durations.
- `hmac_file_server_goroutines`: Current number of active goroutines.

### Systemd Service Example

To run the HMAC File Server as a service on Linux systems, you can create a systemd service file:

```ini
[Unit]
Description=HMAC File Server - Secure File Handling Server
After=network.target

[Service]
ExecStart=/path/to/hmac-file-server -config /path/to/config.toml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl enable hmac-file-server
sudo systemctl start hmac-file-server
```

### Contributing

We welcome contributions! Please fork the repository and submit a pull request, or open an issue for discussion.

### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

