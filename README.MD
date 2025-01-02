# HMAC File Server 2.5-Stable

## Overview
The **HMAC File Server** is a secure and efficient file management solution designed for handling file uploads, downloads, deduplication, and more. With a strong focus on security, scalability, and performance, it integrates seamlessly with various tools to provide a comprehensive file-handling experience.

## Features
- File deduplication
- Configurable TTL for automatic file cleanup
- Secure HMAC-based authentication
- Chunked uploads and downloads
- Virus scanning via ClamAV
- Prometheus metrics integration
- Customizable worker management
- Support for thumbnails and ISO-based storage

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

### Version 2.5-Stable
- **ISO-Based Storage**: Added support for ISO-based storage for specialized use cases.
- **Improved ClamAV Integration**: Concurrent workers introduced for better scanning performance.
- **Timeout Configurations**: Granular timeout options added to manage read, write, and idle connections effectively.
- **Monitor Update**: Bash monitor script is functional, though CPU usage optimization is in progress.

### Version 2.2-Stable
- **Thumbnail Creation**: Introduced automated thumbnail generation for image previews (now deprecated in 2.5).
- **ClamAV Integration**: Added support for malware scanning with configurable scan workers.
- **Redis Support**: Enabled caching and session management through Redis.
- **Enhanced Configuration**: New options for worker auto-adjustment, network event logging, and pre-caching structures.
- **Bug Fixes**: Resolved critical deduplication issue in v2.1, alongside improved error handling and configuration validation.

### Version 2.0-Stable
- **MinFreeBytes Configuration**: Introduced a configuration option to ensure a minimum amount of free disk space is maintained for server operations.
- **Deduplication**: Added automatic deduplication of files based on hashing, improving storage efficiency.
- **Network Monitoring**: Enabled network monitoring with configurable event handling, allowing response to changes in network conditions.
- **ISO Mounting Feature**: Introduced ISO file management with customizable mount options, size, and charset.
- **ClamAV Scanning Enhancements**: Expanded scanning options, allowing specific file types to be targeted.
- **Error Handling and Logging**: Improved mechanisms for debugging and ensuring robust server operations.
- **Auto-Adjust Worker Scaling**: Automatically adjusts the number of workers based on available system resources to optimize performance.

---

## License
This project is licensed under the MIT License. See the LICENSE file for details.

---

### Special Thanks
Thanks to **Thomas Leister** ([GitHub](https://github.com/ThomasLeister/prosody-filer)) for providing a stable base code that inspired the development of HMAC File Server.
