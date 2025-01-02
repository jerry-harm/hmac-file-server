# HMAC File Server 2.5-Stable

## Overview
The **HMAC File Server** ensures secure file uploads and downloads using HMAC authentication. It incorporates rate limiting, CORS support, retries, file versioning, and Unix socket support for enhanced flexibility. Redis integration provides efficient caching and session management. Prometheus metrics and a graceful shutdown mechanism ensure reliable and efficient file handling.

Special thanks to **Thomas Leister** for inspiration drawn from [[prosody-filer](https://github.com/ThomasLeister/prosody-filer)](https://github.com/ThomasLeister/prosody-filer).

## Features
- File deduplication
- Configurable TTL for automatic file cleanup
- Secure HMAC-based authentication
- Chunked uploads and downloads
- Virus scanning via ClamAV
- Prometheus metrics integration
- Customizable worker management
- Support ISO-based storage

## Table of Contents
1. [Installation](#installation)
2. [Configuration](#configuration)
3. [Usage](#usage)
4. [Setup](#setup)
   - [Reverse Proxy](#reverse-proxy)
   - [Systemd Service](#systemd-service)
5. [Building](#building)
6. [Changelog](#changelog)
7. [License](#license)

---

## Installation

### Prerequisites
- Go 1.18 or higher
- Redis server (optional, for caching)
- ClamAV (optional, for virus scanning)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/hmac-file-server.git
   cd hmac-file-server
   ```

2. Build the server:
   ```bash
   go build -o hmac-file-server
   ```

3. Create necessary directories:
   ```bash
   mkdir -p /path/to/hmac-file-server/data/
   mkdir -p /path/to/hmac-file-server/deduplication/
   mkdir -p /path/to/hmac-file-server/thumbnails/
   mkdir -p /path/to/hmac-file-server/iso/
   ```

4. Copy and edit the configuration file:
   ```bash
   cp config.example.toml config.toml
   ```

5. Start the server:
   ```bash
   ./hmac-file-server -config config.toml
   ```

---

## Configuration
The server is configured via a `config.toml` file. Key settings include:

- **Server Settings**: Port, logging, metrics
- **Security**: HMAC secret, TLS options
- **File Management**: TTL, deduplication, uploads, and downloads
- **Thumbnails and ISO**: Generation and mounting settings
- **Workers**: Adjust thread management

For detailed configuration options, refer to the [Wiki](./wiki.md).

---

## Usage
Start the server and access it on the configured port. Use curl or a client library to interact with the API.

### Example
Upload a file:
```bash
curl -X POST -F 'file=@example.jpg' http://localhost:8080/upload
```

---

## Setup

### Reverse Proxy
Set up a reverse proxy using Apache2 or Nginx to handle requests.

#### Apache2 Example
```apache
<VirtualHost *:80>
    ServerName your-domain.com

    ProxyPreserveHost On
    ProxyPass / http://localhost:8080/
    ProxyPassReverse / http://localhost:8080/
</VirtualHost>
```

#### Nginx Example
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Systemd Service
Create a systemd service file for the HMAC File Server:
```ini
[Unit]
Description=HMAC File Server
After=network.target

[Service]
ExecStart=/path/to/hmac-file-server -config /path/to/config.toml
WorkingDirectory=/path/to/hmac-file-server
Restart=always
User=www-data
Group=www-data

[Install]
WantedBy=multi-user.target
```
Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable hmac-file-server
sudo systemctl start hmac-file-server
```

---

## Building
To build for different architectures:

- **Linux (x86_64)**:
  ```bash
  GOOS=linux GOARCH=amd64 go build -o hmac-file-server-linux-amd64
  ```

- **macOS (x86_64)**:
  ```bash
  GOOS=darwin GOARCH=amd64 go build -o hmac-file-server-darwin-amd64
  ```

- **Windows (x86_64)**:
  ```bash
  GOOS=windows GOARCH=amd64 go build -o hmac-file-server-windows-amd64.exe
  ```

---

## Changelog

### Added
- **Deduplication Support:** Automatically remove duplicate files based on SHA256 hashing to save storage space.
- **ISO Container Management:** Create and mount ISO containers for specialized storage needs, enhancing flexibility in file management.
- **Prometheus Metrics Enhancements:** Added detailed metrics for deduplication and ISO container operations to improve monitoring and observability.
- **Redis Integration Improvements:** Enhanced caching mechanisms using Redis for faster access to file metadata and application states.
- **Precaching Feature:** Implemented precaching of file structures on startup to reduce access times for frequently used files.
- **Configuration Options:** Updated `config.toml` to include new settings for deduplication, thumbnails, ISO management, and worker scaling.

### Changed
- **Worker Pool Scaling:** Implemented dynamic adjustment of worker threads based on system resources to optimize performance.
- **Logging Enhancements:** Improved logging for file operations, including detailed information on file extensions and MIME types during uploads.
- **Temporary Path Configuration:** Replaced hardcoded temporary upload directories with a configurable `TempPath` parameter in `config.toml` for greater flexibility.

### Fixed
- **Temporary File Handling:** Resolved issues where temporary `.tmp` files caused "Unsupported file type" warnings by enhancing MIME type detection logic.
- **MIME Type Detection:** Improved MIME type detection to ensure better compatibility and accuracy during file uploads.

### Deprecated
- **Thumbnail Support (Previous Implementation):** Dropped the previous thumbnail support mechanism. This feature will not return in future releases.

---

**Note:** Ensure to update your `config.toml` with the new configuration options to take full advantage of the added features. Refer to the [Configuration](./config.toml) section in the documentation for detailed settings.

---

### Important:
- **GitHub Release:** Create a corresponding GitHub release tagged `v2.6.0` with these updated release notes to inform users of the new features and changes.
- **Migration Steps:** If upgrading from a previous version, review the configuration changes and deprecated features to adjust your setup accordingly.

```toml
[server]
listenport = "8080"
unixsocket = false
storagepath = "./uploads"
metricsenabled = true
metricsport = "9090"
filettl = "8760h"
minfreebytes = "100MB"
autoadjustworkers = true
networkevents = false
temppath = "/tmp"
loggingjson = false
pidfilepath = "/var/run/hmacfileserver.pid"
cleanuponexit = true
precaching = true
filettlenabled = true
deduplicationenabled = true
globalextensions = [".txt", ".pdf", ".png", ".jpg"]

[logging]
level = "info"
file = "/var/log/hmac-file-server.log"
max_size = 100
max_backups = 7
max_age = 30
compress = true

[deduplication]
enabled = true
directory = "/deduplication"

[iso]
enabled = true
size = "1GB"
mountpoint = "/mnt/iso"
charset = "utf-8"
containerfile = "/mnt/iso/container.iso"

[timeouts]
readtimeout = "4800s"
writetimeout = "4800s"
idletimeout = "4800s"

[security]
secret = "changeme"

[versioning]
enableversioning = false
maxversions = 1

[uploads]
resumableuploadsenabled = true
chunkeduploadsenabled = true
chunksize = "64MB"
allowedextensions = [".txt", ".pdf", ".png", ".jpg"]

[downloads]
resumabledownloadsenabled = true
chunkeddownloadsenabled = true
chunksize = "64MB"
allowedextensions = [".txt", ".pdf", ".png", ".jpg"]

[clamav]
clamavenabled = true
clamavsocket = "/var/run/clamav/clamd.ctl"
numscanworkers = 2
scanfileextensions = [".txt", ".pdf", ".png", ".jpg"]

[redis]
redisenabled = true
redisdbindex = 0
redisaddr = "localhost:6379"
redispassword = ""
redishealthcheckinterval = "120s"

[workers]
numworkers = 4
uploadqueuesize = 50

[build]
version = "2.5"
```
