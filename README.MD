
# HMAC File Server

**HMAC File Server** is a secure, scalable, and feature-rich file server with advanced capabilities like HMAC authentication, resumable uploads, chunked uploads, file versioning, and optional ClamAV scanning for file integrity and security. This server is built with extensibility and operational monitoring in mind, including Prometheus metrics support and Redis integration.

## Features

- **HMAC Authentication:** Secure file uploads and downloads with HMAC tokens.
- **File Versioning:** Enable versioning for uploaded files with configurable retention.
- **Chunked and Resumable Uploads:** Handle large files efficiently with support for resumable and chunked uploads.
- **ClamAV Scanning:** Optional virus scanning for uploaded files.
- **Prometheus Metrics:** Monitor system and application-level metrics.
- **Redis Integration:** Use Redis for caching or storing application states.
- **File Expiration:** Automatically delete files after a specified TTL.
- **Graceful Shutdown:** Handles signals and ensures proper cleanup.

---

## Installation

### Prerequisites

- Go 1.20+
- Redis (optional, if Redis integration is enabled)
- ClamAV (optional, if file scanning is enabled)

### Clone and Build

```bash
git clone https://github.com/your-repo/hmac-file-server.git
cd hmac-file-server
go build -o hmac-file-server main.go
```

---

## Configuration

The server configuration is managed through a `config.toml` file. Below are the supported configuration options:

### **Server Configuration**

| Key                    | Description                                         | Example                         |
|------------------------|-----------------------------------------------------|---------------------------------|
| `ListenPort`           | Port or Unix socket to listen on                    | `":8080"`                      |
| `UnixSocket`           | Use a Unix socket (`true`/`false`)                  | `false`                        |
| `Secret`               | Secret key for HMAC authentication                 | `"your-secret-key"`            |
| `StoreDir`             | Directory to store uploaded files                  | `"/mnt/storage/hmac-file-server"` |
| `LogLevel`             | Logging level (`info`, `debug`, etc.)               | `"info"`                       |
| `LogFile`              | Log file path (optional)                           | `"/var/log/hmac-file-server.log"` |
| `MetricsEnabled`       | Enable Prometheus metrics (`true`/`false`)          | `true`                         |
| `MetricsPort`          | Prometheus metrics server port                     | `"9090"`                       |
| `FileTTL`              | File Time-to-Live duration                         | `"168h0m0s"`                   |

### **Uploads**

| Key                        | Description                                   | Example     |
|----------------------------|-----------------------------------------------|-------------|
| `ResumableUploadsEnabled`  | Enable resumable uploads                     | `true`      |
| `ChunkedUploadsEnabled`    | Enable chunked uploads                       | `true`      |
| `ChunkSize`                | Chunk size for chunked uploads (bytes)       | `1048576`   |
| `AllowedExtensions`        | Allowed file extensions for uploads          | `[".png", ".jpg"]` |

### **Time Settings**

| Key             | Description                    | Example  |
|------------------|--------------------------------|----------|
| `ReadTimeout`    | HTTP server read timeout      | `"2h"`   |
| `WriteTimeout`   | HTTP server write timeout     | `"2h"`   |
| `IdleTimeout`    | HTTP server idle timeout      | `"2h"`   |

### **ClamAV Configuration**

| Key                | Description                               | Example                          |
|--------------------|-------------------------------------------|----------------------------------|
| `ClamAVEnabled`    | Enable ClamAV virus scanning (`true`)     | `true`                          |
| `ClamAVSocket`     | Path to ClamAV Unix socket               | `"/var/run/clamav/clamd.ctl"`   |
| `NumScanWorkers`   | Number of workers for file scanning       | `2`                             |

### **Redis Configuration**

| Key                        | Description                      | Example           |
|----------------------------|----------------------------------|-------------------|
| `RedisEnabled`             | Enable Redis integration         | `true`            |
| `RedisDBIndex`             | Redis database index             | `0`               |
| `RedisAddr`                | Redis server address             | `"localhost:6379"`|
| `RedisPassword`            | Password for Redis authentication| `""`              |
| `RedisHealthCheckInterval` | Health check interval for Redis  | `"30s"`           |

---

## Running the Server

### Basic Usage

Run the server with a configuration file:

```bash
./hmac-file-server -config ./config.toml
```

### Metrics Server

If `MetricsEnabled` is `true`, the Prometheus metrics server will run on the port specified in `MetricsPort` (default: `9090`).

---

## Development Notes

- **Versioning:** Enabled via `EnableVersioning`. Ensure `MaxVersions` is set appropriately to prevent storage issues.
- **File Cleaner:** The file cleaner runs hourly and deletes files older than the configured `FileTTL`.
- **Redis Health Check:** Automatically monitors Redis connectivity and logs warnings on failure.

---

## Testing

To run the server locally for development:

```bash
go run main.go -config ./config.toml
```

Use tools like **cURL** or **Postman** to test file uploads and downloads.

### Example File Upload with HMAC Token

```bash
curl -X PUT -H "Authorization: Bearer <HMAC-TOKEN>" -F "file=@example.txt" http://localhost:8080/uploads/example.txt
```

Replace `<HMAC-TOKEN>` with a valid HMAC signature generated using the configured `Secret`.

---

## Monitoring

Prometheus metrics include:
- File upload/download durations
- Memory usage
- CPU usage
- Active connections
- HTTP requests metrics (total, method, path)
