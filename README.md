
# HMAC File Server

## Overview

HMAC File Server is a secure server for uploading and downloading files using HMAC signatures for authentication. It includes rate-limiting, auto-banning, file access retries, and disk space checks. It supports CORS, Unix sockets, HTTP/2, and graceful shutdowns, ensuring efficient and safe file transfers.

### Key Features
- **HMAC Authentication**: Secure file transfers using HMAC signatures.
- **Retry Mechanism**: Automatic retries for file access and downloads.
- **Disk Space Checks**: Prevents uploads if disk space is low.
- **Rate Limiting & Auto-Banning**: Protects against abuse by limiting failed access attempts.
- **Auto-File Deletion**: Automatically delete files older than a configurable period.
- **HTTP/2 & CORS Support**: For faster and cross-origin file transfers.
- **Systemd Support**: Easily manage as a service.

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
ListenPort = "8080"
UnixSocket = false
Secret = "your-secret-key"
StoreDir = "/var/lib/hmac-file-server"
UploadSubDir = "uploads"
LogLevel = "info"
MaxRetries = 5
RetryDelay = 2
EnableGetRetries = true
BlockAfterFails = 5
BlockDuration = 300
AutoUnban = true
AutoBanTime = 600
DeleteFiles = true
DeleteFilesAfterPeriod = "30d"  # 30 days
WriteReport = true
ReportPath = "/var/log/hmac-file-server/deleted-files-report.log"
```

- **ListenPort**: Port for the server to listen on.
- **UnixSocket**: Option to use Unix sockets instead of TCP.
- **StoreDir**: Directory where files will be stored.
- **Auto-File Deletion**: Configure to delete files after a set period.
- **CORS**: Add custom headers for CORS support when using web-based clients.

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

## ejabberd Integration

Configure ejabberd to work with the HMAC File Server:

```yaml
mod_http_upload:
    max_size: 536870912  # 512MB max upload size
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

This configuration allows ejabberd to interact with the file server using HTTP upload for file transfers.

---

## Acknowledgements

Special thanks to **Thomas Leister** for his contributions and inspiration for this project. His work has laid the foundation for the development of this secure file handling solution.
