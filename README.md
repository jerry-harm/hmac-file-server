
# HMAC File Server

## Overview

HMAC File Server is a secure server for uploading and downloading files using HMAC signatures for authentication. It includes rate-limiting, auto-banning, file access retries, and disk space checks. It supports CORS, Unix sockets, HTTP/2, and graceful shutdowns, ensuring efficient and safe file transfers.

### Key Features
- **HMAC Authentication**: Secure file transfers using HMAC signatures.
- **Retry Mechanism**: Automatic retries for file access and downloads.
- **Disk Space Checks**: Prevents uploads if disk space is low.
- **Rate Limiting & Auto-Banning**: Protects against abuse by limiting failed access attempts.
- **Auto-File Deletion**: Automatically deletes files older than a configurable period.
- **Max Upload Size**: Set maximum upload size (default is 1GB) for better control over file handling.
- **Multicore Support**: Efficiently uses all available CPU cores for optimized performance.
- **Buffer Configuration**: Enables buffering for read and write operations to improve performance.
- **Automatic Caching**: Introduced automatic caching through goroutines to enhance performance and reduce latency for frequently accessed file metadata.
- **HTTP/2 & CORS Support**: For faster and cross-origin file transfers.
- **Systemd Support**: Easily managed as a service.
- **Prometheus Metrics**: Exposes metrics for monitoring and performance tracking, enabling integration with Prometheus for observability.
- **Interactive Configuration**: Prompts for configuration values if the `config.toml` file is missing, ensuring easy setup.
- **File Versioning**: Enable file versioning to track file changes.

---

## Installation and Compilation

### Prerequisites
- **Go**: Ensure Go is installed on your system. [Download Go](https://golang.org/dl/).
- **Git**: Verify Git is installed.

### Build Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/PlusOne/hmac-file-server.git
   cd hmac-file-server
   ```

2. **Compile the Project**:
   ```bash
   GOARCH=amd64 GOOS=linux go build -o hmac-file-server
   ```

3. **Run the Application**:
   ```bash
   ./hmac-file-server --config=config.toml
   ```

---

## Configuration and Running

The server is configured using a `config.toml` file. Below is a sample configuration:

```toml
# Server listening port for TCP
ListenPort = ":8080"

# Use Unix socket (true or false)
UnixSocket = false

# Path to the Unix socket (used if UnixSocket is true)
# UnixSocketPath = "/home/hmac-file-server/hmac.sock"

# Secret key for HMAC authentication
Secret = "your-hmac-secret-key"  # Placeholder for the actual HMAC secret key

# Directories for storing files
StoreDir = "/mnt/storage/hmac-file-server/"
UploadSubDir = "upload"

# Logging level ("debug", "info", "warn", "error")
LogLevel = "debug"

# Log file path (optional). Leave empty to log to console
LogFile = "/var/log/hmac-file-server.log"

# Retry settings
MaxRetries = 5
RetryDelay = 2
EnableGetRetries = true

# Max Upload Size
MaxUploadSize = 1073741824  # 1 GB in bytes
BufferSize = 65536           # 64 KB in bytes
MinFreeSpaceThreshold = 104857600  # 100 MB

# Rate limiting and banning
BlockAfterFails = 5
BlockDuration = 300
AutoUnban = true
AutoBanTime = 600

# File deletion settings
DeleteFiles = true
DeleteFilesAfterPeriod = "1y"  # Can be in days (d), months (m), or years (y)
DeleteFilesReport = true
DeleteFilesReportPath = "/home/hmac-file-server/deleted_files.log"

# CPU core settings
NumCores = "auto"  # Set to "auto" to use all available cores or a specific number like "2", "4", etc.

# HMAC Secret Re-ask Configuration
ReaskSecretEnabled = true                    # Enable or disable periodic secret reasking
ReaskSecretInterval = "1h"                   # Interval for reasking the secret (e.g., "24h" for 24 hours)

# Monitoring Configuration
MetricsEnabled = true                         # Enable Prometheus metrics
MetricsPort = ":9090"                         # Port for metrics endpoint

# File versioning configuration
FileVersioningEnabled = true                 # Enable file versioning to track file changes
```

### Interactive Configuration
If `config.toml` is not found, the server will prompt you to input configuration values, creating the file with the provided settings.

### Running the server
```bash
./hmac-file-server --config=config.toml
```

---

## Systemd Integration

To manage the HMAC File Server as a systemd service, use the following configuration:

```ini
[Unit]
Description=HMAC File Server - Secure File Handling Server
After=network.target

[Service]
ExecStart=/path/to/hmac-file-server --config=/path/to/config.toml
WorkingDirectory=/path/to/working-directory
Restart=on-failure
User=hmac-file-server
Group=hmac-file-server
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
```

- Place this file in `/etc/systemd/system/hmac-file-server.service`.
- Reload systemd and enable the service:
  ```bash
  sudo systemctl daemon-reload
  sudo systemctl enable hmac-file-server.service
  sudo systemctl start hmac-file-server.service
  ```

---

## ejabberd HTTP Upload Integration

Configure ejabberd to work with the HMAC File Server:

```yaml
mod_http_upload:
    max_size: 1073741824  # 1GB max upload size
    thumbnail: true  # Optional thumbnail generation
    put_url: https://share.example.com
    get_url: https://share.example.com
    docroot: /mnt/storage/ejabberd
    external_secret: "replace_with_hmac_file_server_secret"
    custom_headers:
      "Access-Control-Allow-Origin": "*"
      "Access-Control-Allow-Methods": "GET,HEAD,PUT,OPTIONS"
      "Access-Control-Allow-Headers": "Content-Type"
```

---

## Prosody HTTP Upload Integration

You can integrate the HMAC File Server with **Prosody** for HTTP file uploads. Below is a sample configuration for `mod_http_upload`:

```lua
Component "upload.example.com" "http_upload"
    http_upload_path = "/upload/"
    http_external_url = "https://share.example.com"
    max_size = 1073741824 -- 1GB max upload size
    docroot = "/mnt/storage/prosody_uploads"
    external_secret = "replace_with_hmac_file_server_secret"
    custom_headers = {
        ["Access-Control-Allow-Origin"] = "*";
        ["Access-Control-Allow-Methods"] = "GET, HEAD, PUT, OPTIONS";
        ["Access-Control-Allow-Headers"] = "Content-Type";
    }

    -- Optional thumbnail support
    thumbnail = true
```

---

## Acknowledgements

Special thanks to **Thomas Leister** for his contributions and inspiration for this project. His work has laid the foundation for the development of this secure file handling solution.

---

## Download Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/PlusOne/hmac-file-server.git
   ```

2. **Follow the build and configuration steps** listed above to compile and run the server on your environment.

---

### Accessing the Server via Unix Socket:

To interact with the server via a Unix socket, you can use tools like `curl`. Here’s an example command to make a request:

```bash
curl --unix-socket /home/hmac-file-server/hmac.sock http://localhost/upload/
```

This command uses the Unix socket to interact with the server.
