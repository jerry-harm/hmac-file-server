
# HMAC File Server

## Overview
The HMAC File Server is a secure file handling server that uses HMAC (Hash-based Message Authentication Code) for authenticating file uploads and downloads. It supports features like file versioning, resumable uploads, and integration with Redis for caching.

## Features
- HMAC validation for secure file uploads and downloads
- Chunked file uploads
- Redis integration for caching upload metadata
- Dynamic CPU core configuration
- File versioning with retention policy
- File expiration and automatic deletion
- Health checks for Redis connectivity
- Prometheus metrics for monitoring

## Installation
1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/hmac-file-server.git
   cd hmac-file-server
   ```

2. **Install dependencies**:
   Ensure you have Go installed and run:
   ```bash
   go mod tidy
   ```

3. **Build the server**:
   ```bash
   go build -o hmac-file-server
   ```

## Configuration
Create a `config.toml` file in the same directory as the executable with the following structure:
```toml
ListenPort = ":8080"
UnixSocket = false
Secret = "your-secret-key"
StoreDir = "/path/to/store/files"
UploadSubDir = "uploads"
LogLevel = "info"
LogFile = "server.log"
MetricsEnabled = true
MetricsPort = ":9090"
FileTTL = "30d"
ResumableUploadsEnabled = true
EnableVersioning = true
MaxVersions = 5
```

## Running the Server
To start the server, run:
```bash
./hmac-file-server -config ./config.toml
```

## Metrics and Health Check
The server exposes Prometheus metrics at the `/metrics` endpoint. To check the server's health and Redis connectivity, ensure the health check functionality is enabled in the configuration.

## License
This project is licensed under the MIT License.
