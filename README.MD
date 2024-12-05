# HMAC File Server

**HMAC File Server** is a secure, scalable, and feature-rich file server with advanced capabilities like HMAC authentication, resumable uploads, chunked uploads, file versioning, and optional ClamAV scanning for file integrity and security. This server is built with extensibility and operational monitoring in mind, including Prometheus metrics support and Redis integration.

---

## Features

- **HMAC Authentication:** Secure file uploads and downloads with HMAC tokens.
- **File Versioning:** Enable versioning for uploaded files with configurable retention.
- **Chunked and Resumable Uploads:** Handle large files efficiently with support for resumable and chunked uploads.
- **ClamAV Scanning:** Optional virus scanning for uploaded files.
- **Prometheus Metrics:** Monitor system and application-level metrics.
- **Redis Integration:** Use Redis for caching or storing application states.
- **File Expiration:** Automatically delete files after a specified TTL.
- **Graceful Shutdown:** Handles signals and ensures proper cleanup.
- **Deduplication:** Remove duplicate files based on hashing for storage efficiency.

---

## Repository

- **Primary Repository**: [GitHub Repository](https://github.com/your-repo/hmac-file-server)
- **Alternative Repository**: [uuxo.net Git Repository](https://git.uuxo.net/uuxo/hmac-file-server)

---

## Installation

### Prerequisites

- Go 1.20+
- Redis (optional, if Redis integration is enabled)
- ClamAV (optional, if file scanning is enabled)

### Clone and Build

```bash
# Clone from the primary repository
git clone https://github.com/PlusOne/hmac-file-server.git

# OR clone from the alternative repository
git clone https://git.uuxo.net/uuxo/hmac-file-server.git

cd hmac-file-server
go build -o hmac-file-server main.go
```

---

## Configuration

The server configuration is managed through a `config.toml` file. Below are the supported configuration options:

---

## Example `config.toml`

```toml
[server]
ListenPort = "8080"
UnixSocket = false
StoragePath = "./uploads"
LogLevel = "info"
LogFile = ""
MetricsEnabled = true
MetricsPort = "9090"
FileTTL = "8760h" # 365 days
DeduplicationEnabled = true
MinFreeBytes = "100MB"

[timeouts]
ReadTimeout = "4800s"
WriteTimeout = "4800s"
IdleTimeout = "4800s"

[security]
Secret = "changeme"

[versioning]
EnableVersioning = false
MaxVersions = 1

[uploads]
ResumableUploadsEnabled = true
ChunkedUploadsEnabled = true
ChunkSize = "8192"
AllowedExtensions = [".txt", ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".svg", ".webp", ".wav", ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".mpeg", ".mpg", ".m4v", ".3gp", ".3g2", ".mp3", ".ogg"]

[clamav]
ClamAVEnabled = true
ClamAVSocket = "/var/run/clamav/clamd.ctl"
NumScanWorkers = 2
ScanFileExtensions = [".exe", ".dll", ".bin", ".com", ".bat", ".sh", ".php", ".js"]

[redis]
RedisEnabled = true
RedisAddr = "localhost:6379"
RedisPassword = ""
RedisDBIndex = 0
RedisHealthCheckInterval = "120s"

[workers]
NumWorkers = 2
UploadQueueSize = 50

[iso]
Enabled = true
Size = "2TB" # Example ISO size changed to 2TB
MountPoint = "/mnt/iso"
Charset = "utf-8"
```

---

## Running the Server

### Basic Usage

Run the server with a configuration file:

```bash
./hmac-file-server -config ./config.toml
```

---

### Metrics Server

If `MetricsEnabled` is set to `true`, the Prometheus metrics server will be available on the port specified in `MetricsPort` (default: `9090`).

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

---

## Additional Features

- **Deduplication**: Automatically remove duplicate files based on hashing.
- **Versioning**: Store multiple versions of files and keep a maximum of `MaxVersions` versions.
- **ClamAV Integration**: Scan uploaded files for viruses using ClamAV.
- **Redis Caching**: Utilize Redis for caching file metadata for faster access.

This release ensures an efficient and secure file management system, tailored to environments requiring robust data handling capabilities.
