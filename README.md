
# HMAC File Server - Version 2.0

**HMAC File Server** is a secure file handling server that uses HMAC (Hash-based Message Authentication Code) for authentication, offering a secure way to upload and retrieve files. It supports Redis for caching, PostgreSQL/MySQL for fallback database functionality, and Prometheus for metrics collection. This release focuses on improved performance, stability, and flexibility.

## Features

- **HMAC-based Authentication**: Secure file uploads and downloads with HMAC validation.
- **Redis Integration**: For fast lookups and session handling (optional).
- **Fallback to Databases**: Support for both PostgreSQL and MySQL as fallback storage (optional).
- **Basic HTTP Caching**: Implements `Cache-Control`, `Last-Modified`, and `ETag` headers for optimized file serving.
- **Prometheus Metrics**: Collects metrics for file uploads, errors, and server performance.
- **CORS Support**: Allows cross-origin file uploads.
- **Graceful Shutdown**: Supports graceful shutdowns to safely handle ongoing operations.

---

## Table of Contents

1. [Installation](#installation)
2. [Configuration](#configuration)
3. [Usage](#usage)
4. [API Endpoints](#api-endpoints)
5. [Metrics](#metrics)
6. [Logging](#logging)
7. [Contributing](#contributing)
8. [License](#license)

---

## Installation

### Requirements

- **Go** (version 1.20 or higher)
- **Redis** (optional)
- **PostgreSQL** or **MySQL** (optional, for fallback database)
- **Prometheus** (for monitoring)

### Clone and Build

```bash
git clone https://github.com/yourusername/hmac-file-server.git
cd hmac-file-server
go build -o hmac-file-server
```

### Systemd Service (Optional)

You can configure the server as a systemd service. Example `hmac-file-server.service`:

```ini
[Unit]
Description=HMAC File Server - Secure File Handling Server
After=network.target

[Service]
ExecStart=/path/to/hmac-file-server --config /path/to/config.toml
Restart=on-failure
User=hmac-server
Group=hmac-server
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Place this file in `/etc/systemd/system/hmac-file-server.service`, then enable and start the service:

```bash
sudo systemctl enable hmac-file-server
sudo systemctl start hmac-file-server
```

---

## Configuration

All configuration settings are managed through a `config.toml` file. Below is an example configuration:

```toml
# Server settings
ListenPort = ":8080"
UnixSocket = false
AuthenticationKey = "secure-wisdom-orbit-echo"  # Authentication key for secure communication
StoreDir = "/mnt/storage/hmac-file-server/"
UploadSubDir = "upload"
LogLevel = "info"
LogFile = "/var/log/hmac-file-server.log"
MaxRetries = 5
RetryDelay = 2
MetricsEnabled = true
MetricsPort = ":9090"
ChunkSize = 65536

# Redis configuration (optional)
RedisAddr = "localhost:6379"
RedisPassword = ""
RedisDB = 0

# Fallback database (optional)
FallbackEnabled = true
FallbackDBType = "postgres"  # "postgres" or "mysql"
FallbackDBHost = "localhost"
FallbackDBUser = "your_db_user"
FallbackDBPassword = "your_db_password"
FallbackDBName = "your_db_name"
```

---

## Usage

To start the server:

```bash
./hmac-file-server --config /path/to/config.toml
```

### Uploading a File

To upload a file using the authentication key, you must provide a valid signature in the URL.

**PUT** `/upload/<path>/<filename>?v=<auth-signature>`

- The authentication signature is calculated as:
  
  ```
  Signature = HMAC_SHA256(auth_key, <filename> + " " + <file_size>)
  ```

Example using `curl`:

```bash
curl -X PUT --data-binary @file.jpg "http://localhost:8080/upload/folder/file.jpg?v=<auth-signature>"
```

### Downloading a File

**GET** `/upload/<path>/<filename>`

Example:

```bash
curl -X GET "http://localhost:8080/upload/folder/file.jpg"
```

---

## API Endpoints

| Method | Endpoint                                   | Description                         |
|--------|--------------------------------------------|-------------------------------------|
| `PUT`  | `/upload/<path>/<filename>?v=<auth-signature>`  | Upload a file with signature       |
| `GET`  | `/upload/<path>/<filename>`                | Download a file                    |
| `OPTIONS` | `/upload/<path>/<filename>`             | Preflight request (CORS support)   |
| `HEAD` | `/upload/<path>/<filename>`                | Get file metadata without the body |

---

## Metrics

The HMAC File Server supports Prometheus metrics. Metrics are served on a dedicated endpoint when enabled:

**Metrics Endpoint**: `/metrics`

Sample Prometheus metrics:

- `file_server_upload_duration_seconds`: Histogram for file upload duration.
- `file_server_upload_errors_total`: Counter for total upload errors.
- `file_server_uploads_total`: Counter for successful uploads.

Enable metrics by setting `MetricsEnabled = true` and configuring `MetricsPort`.

---

## Logging

The server logs system information at startup, including:

- Operating System
- Architecture
- Number of CPUs
- Go version
- Total, free, and used memory
- Hostname and uptime

Logs are stored in the file specified by `LogFile` in the `config.toml`.

### Example Log Output:

```bash
2024-10-23T08:12:35Z [INFO] Starting HMAC File Server - v2.0
2024-10-23T08:12:35Z [INFO] Operating System: linux
2024-10-23T08:12:35Z [INFO] Architecture: amd64
2024-10-23T08:12:35Z [INFO] Number of CPUs: 4
2024-10-23T08:12:35Z [INFO] Go Version: go1.20
2024-10-23T08:12:35Z [INFO] Total Memory: 8192 MB
2024-10-23T08:12:35Z [INFO] Free Memory: 5120 MB
2024-10-23T08:12:35Z [INFO] Hostname: server.local
2024-10-23T08:12:35Z [INFO] Connected to Redis.
```

---

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-new-feature`.
3. Commit your changes: `git commit -am 'Add some feature'`.
4. Push to the branch: `git push origin feature/my-new-feature`.
5. Submit a pull request.

---

## License

HMAC File Server is open-source software licensed under the [MIT License](LICENSE).

Mit ❤️ codiert – während um uns die Welt im Chaos versinkt!
