
# HMAC File Server

HMAC File Server is a secure server for uploading and downloading files using HMAC signatures for authentication. It includes rate-limiting, auto-banning, file access retries, disk space checks, dynamic resource management, and the ability to resume file uploads.

## Key Features

- **HMAC Authentication**: Secure file transfers using HMAC signatures.
- **Upload Resume Support**: Ability to resume uploads from a specified offset, improving fault tolerance and efficiency.
- **Retry Mechanism**: Automatic retries for file access and downloads.
- **Disk Space Checks**: Prevents uploads if disk space is low, configurable via `MinFreeSpaceThreshold`.
- **Rate Limiting & Auto-Banning**: Protects against abuse by limiting failed access attempts.
- **Auto-File Deletion**: Automatically delete files older than a configurable period.
- **Max Upload Size**: Dynamically managed based on memory detection (Low, Medium, High) with configurable options for manual overrides.
- **Multicore Support**: Efficiently uses available CPU cores for optimized performance.
- **Buffer Configuration**: Dynamic buffer size management based on available memory, with configurable manual overrides.
- **Prometheus Metrics**: Tracks performance, including CPU, memory usage, upload duration, and total downloads.
- **Interactive Configuration**: The server can now prompt users for missing configuration parameters if `config.toml` is not found, automatically generating the configuration file.

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

If the `config.toml` file is not found, the server will interactively prompt for configuration parameters and generate the configuration file automatically.

---

## Configuration

The server is configured using a `config.toml` file. If not provided, you can generate the file interactively by running the server.

Here is an example `config.toml`:

```toml
# Server listening port for TCP (used if UnixSocket is false)
ListenPort = ":8080"

# Use Unix socket (true or false)
UnixSocket = false

# Path to the Unix socket (used if UnixSocket is true)
# UnixSocketPath = "/home/hmac-file-server/hmac.sock"

# Secret key for HMAC authentication
Secret = "your-hmac-secret-key"

# Directories for storing files
StoreDir = "/mnt/storage/hmac-file-server/"
UploadSubDir = "upload"

# Logging level ("debug", "info", "warn", "error")
LogLevel = "debug"

# Retry settings
MaxRetries = 5
RetryDelay = 2
EnableGetRetries = true

# Dynamic resource management based on memory size.
# If not set, values will be adjusted automatically:
# - Low Memory (<2 GB): Buffer size = 32 KB, MaxUploadSize = 512 MB
# - Medium Memory (2 GB - 8 GB): Buffer size = 64 KB, MaxUploadSize = 1 GB
# - High Memory (>8 GB): Buffer size = 128 KB, MaxUploadSize = 2 GB
MaxUploadSize = 1073741824  # 1 GB in bytes
BufferSize = 65536          # 64 KB in bytes

# Minimum free space threshold before uploads are blocked (in bytes)
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
NumCores = "auto"  # Set to "auto" to use all available cores

# Buffer pool configuration
BufferEnabled = true

# HMAC Secret Re-ask Configuration
ReaskSecretEnabled = true
ReaskSecretInterval = "24h"

# Monitoring Configuration
MetricsEnabled = true
MetricsPort = ":9090"
```

---

## Interactive Configuration Generation

If `config.toml` is missing, the server will prompt for the following inputs interactively:

1. Server Listen Port
2. Use Unix Socket (true/false)
3. Secret for HMAC Authentication
4. Store Directory and Upload Subdirectory
5. Log Level
6. Max Upload Size and Buffer Size (with dynamic memory management defaults)
7. Minimum Free Space Threshold
8. Retry and Rate Limiting settings
9. File Deletion settings
10. CPU Cores and Buffer Pool settings
11. Metrics and Monitoring configuration

The generated `config.toml` will be saved in the working directory.

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

## Monitoring and Metrics

Prometheus metrics are exposed on the `/metrics` endpoint if `MetricsEnabled = true`.

---

## ejabberd HTTP Upload Integration

Configure ejabberd to work with the HMAC File Server:

```yaml
mod_http_upload:
    max_size: 1073741824  # 1GB max upload size
    put_url: https://share.example.com
    get_url: https://share.example.com
    docroot: /mnt/storage/ejabberd
    external_secret: "replace_with_hmac_file_server_secret"
```

---

## Prosody HTTP Upload Integration

To integrate HMAC File Server with **Prosody**, use the following configuration:

```lua
Component "upload.example.com" "http_upload"
    http_upload_path = "/upload/"
    http_external_url = "https://share.example.com"
    max_size = 1073741824 -- 1GB max upload size
    docroot = "/mnt/storage/prosody_uploads"
    external_secret = "replace_with_hmac_file_server_secret"
```

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
