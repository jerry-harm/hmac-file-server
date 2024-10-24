
# HMAC File Server

## Overview
This is a secure file server that uses HMAC-based authentication for secure file handling. The server supports multiple protocols (`v`, `v2`, `token`) and integrates features like chunked uploads, rate limiting, Redis, PostgreSQL, and MySQL fallback support. Prometheus metrics are available to monitor server performance.

## Features
- **HMAC Authentication**: Supports multiple versions of HMAC-based authentication (`v`, `v2`, `token`).
- **Chunked Uploads**: Handles large file uploads through chunking.
- **Rate Limiting**: Supports configurable upload rate limiting.
- **Fallback Databases**: Supports Redis as the primary store and fallback options for PostgreSQL or MySQL.
- **Prometheus Metrics**: Exposes Prometheus metrics for monitoring upload durations and errors.
- **CORS Support**: Adds CORS headers for cross-origin support.

## Installation

### Prerequisites
- Go 1.16 or later
- Redis (optional)
- PostgreSQL or MySQL (optional)
- Prometheus (optional, for metrics)

### Clone Repository
```bash
git clone https://github.com/your-repo/hmac-file-server.git
cd hmac-file-server
```

### Build
To build the server:
```bash
go build -o hmac-file-server main.go
```

### Configuration
Create a `config.toml` file with the following structure:
```toml
ListenPort = ":8080"
UnixSocket = false
Secret = "your-hmac-secret"
StoreDir = "/path/to/store"
UploadSubDir = "upload"
LogLevel = "info"
LogFile = "/path/to/log/file.log"

# Redis configuration (optional)
RedisAddr = "localhost:6379"
RedisPassword = ""
RedisDB = 0

# Fallback Database (optional)
FallbackEnabled = true
FallbackDBType = "postgres" # or "mysql"
FallbackDBHost = "localhost"
FallbackDBUser = "dbuser"
FallbackDBPassword = "dbpassword"
FallbackDBName = "dbname"

# Metrics (optional)
MetricsEnabled = true
MetricsPort = ":9090"

# Upload settings
ChunkSize = 1048576  # 1 MB
UploadMaxSize = 1073741824  # 1 GB
MaxBytesPerSecond = 524288  # 512 KB/s
```

### Running the Server
Start the server by providing the path to your `config.toml`:
```bash
./hmac-file-server -config ./config.toml
```

### Prometheus Metrics
If enabled, you can access metrics at `/metrics` on the configured `MetricsPort`.

![image](https://github.com/user-attachments/assets/36b42cc0-62c0-4d15-97f2-08091db23c8a)

### Example of HMAC Authentication
For `v` protocol:
```bash
hmac-sha256("file/path 1024")
```

For `v2` or `token` protocol:
```bash
hmac-sha256("file/path\x00content-length\x00content-type")
```

### License
This project is licensed under the MIT License.
