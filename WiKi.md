# HMAC File Server

**HMAC File Server** is a secure, scalable, and feature-rich file server with advanced capabilities like HMAC authentication, resumable uploads, chunked uploads, file versioning, and optional ClamAV scanning for file integrity and security. This server is built with extensibility and operational monitoring in mind, including Prometheus metrics support and Redis integration.

> **Credits:** The **HMAC File Server** is based on the source code of [Thomas Leister's prosody-filer](https://github.com/ThomasLeister/prosody-filer). Many features and design elements have been inspired or derived from this project.

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
- **Auto-Adjust Worker Scaling:** Dynamically optimize HMAC and ClamAV workers based on system resources when enabled.
- **Thumbnail Support:** Generate smaller versions of uploaded images for efficient storage and quick access.

---

## Repository

- **Primary Repository**: [GitHub Repository](https://github.com/PlusOne/hmac-file-server)
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

### Building for Different Architectures

To build the HMAC File Server for different architectures, use the following commands:

#### Build for `arm64`
```bash
cd /path/to/hmac-file-server
GOOS=linux GOARCH=arm64 go build -o ~/Temp/hmac-file-server-2.2-stable_arm64 main.go
```

#### Build for `amd64`
```bash
cd /path/to/hmac-file-server
GOOS=linux GOARCH=amd64 go build -o ~/Temp/hmac-file-server-2.2-stable_amd64 main.go
```

Replace `/path/to/hmac-file-server` with the actual path to your project directory. These commands will generate the binaries for `arm64` and `amd64` architectures and place them in the `~/Temp` directory.

---

## Configuration

The server configuration is managed through a `config.toml` file. Below are the supported configuration options:

### Auto-Adjust Feature

When `AutoAdjustWorkers` is enabled, the number of workers for HMAC operations and ClamAV scans is dynamically determined based on system resources. This ensures efficient resource utilization.

If `AutoAdjustWorkers = true`, the values for `NumWorkers` and `NumScanWorkers` in the configuration file will be ignored, and the server will automatically adjust these values.

### Network Events Monitoring

Setting `NetworkEvents = false` in the server configuration disables the logging and tracking of network-related events within the application. This means that functionalities such as monitoring IP changes or recording network activity will be turned off.

### Precaching

The `precaching` feature allows the server to pre-cache storage paths for faster access. This can improve performance by reducing the time needed to access frequently used storage paths.

### Thumbnail Support

- New configuration options in `[thumbnails]` to enable or disable generating image thumbnails, set the thumbnail size, and configure concurrency for thumbnail generation.

---

## New Features

### Deduplication Support

- **Description:** Added support for file deduplication to save storage space by storing a single copy of identical files.
- **Configuration:**
  ```toml
  [deduplication]
  enabled = true
  directory = "/mnt/hmac-storage/deduplication/"
  ```

### Thumbnail Support

- **Description:** Added support for thumbnail creation to generate smaller versions of uploaded images.
- **Configuration:**
  ```toml
  [thumbnails]
  enabled = true
  directory = "/mnt/hmac-storage/thumbnails/"
  size = "200x200"
  concurrency = 5
  thumbnailintervalscan = "24h"
  ```

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
FileTTL = "2y"  # Updated from "1y"
FileTTLEnabled = true  # Enable or disable file TTL
MinFreeBytes = "5GB"  # Updated from "100MB"
AutoAdjustWorkers = true  # Enable auto-adjustment for worker scaling
NetworkEvents = false     # Updated from true
PIDFilePath = "./hmac-file-server.pid"
Precaching = false  # Updated from true
#globalextensions = ["*"]  # Commented out as per working example

[deduplication]
enabled = true
directory = "/mnt/nfs_vol01/hmac-file-server/deduplication/"

[logging]
level = "debug"  # Updated from "info"
file = "/var/log/hmac-file-server.log"
max_size = 100
max_backups = 7
max_age = 30
compress = true

[thumbnails]
enabled = true
directory = "/mnt/nfs_vol01/hmac-file-server/thumbnails/"
size = "200x200"
thumbnailintervalscan = "1h"  # Updated from "24h"
concurrency = 5

[iso]
enabled = false
size = "1TB"
mountpoint = "/mnt/nfs_vol01/hmac-file-server/iso/"
charset = "utf-8"

[timeouts]
ReadTimeout = "3600s"
WriteTimeout = "3600s"
IdleTimeout = "3600s"

[security]
Secret = "a-woky-is-not-a-puppet-which-is-eJabberD"

[versioning]
EnableVersioning = false
MaxVersions = 1

[uploads]
ResumableUploadsEnabled = false  # Updated from true
ChunkedUploadsEnabled = false  # Updated from true
ChunkSize = "32MB"  # Updated from "64MB"
AllowedExtensions = [
    ".txt", ".pdf", ".png", ".jpg", ".jpeg", ".gif",
    ".bmp", ".tiff", ".svg", ".webp", ".wav", ".mp4",
    ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm",
    ".mpeg", ".mpg", ".m4v", ".3gp", ".3g2", ".mp3", ".ogg"
]

[downloads]
ChunkedDownloadsEnabled = false  # Updated from true
ChunkSize = "32MB"  # Updated from "64MB"
AllowedExtensions = [
    ".txt", ".pdf", ".png", ".jpg", ".jpeg", ".gif",
    ".bmp", ".tiff", ".svg", ".webp", ".wav", ".mp4",
    ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm",
    ".mpeg", ".mpg", ".m4v", ".3gp", ".3g2", ".mp3", ".ogg"
]

[clamav]
ClamAVEnabled = true
ClamAVSocket = "/var/run/clamav/clamd.ctl"
NumScanWorkers = 4  # Updated from 2
ScanFileExtensions = [
    ".exe", ".dll", ".bin", ".com",
    ".bat", ".sh", ".php", ".js"
]

[redis]
RedisEnabled = true
RedisDBIndex = 0
RedisAddr = "localhost:6379"
RedisPassword = ""
RedisHealthCheckInterval = "120s"

[workers]
NumWorkers = 4
UploadQueueSize = 500
MaxConcurrentOperations = 10  # Updated from 10 (no change, included for clarity)
NetworkEventBuffer = 100
PerformanceMonitorInterval = "5m"
MetricsUpdateInterval = "10s"

[precache]
RedisEnabled = true
RedisAddr = "localhost:6379"
StaticIndexFile = "./static_index.json"

[build]
Version = "v2.4"
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

Replace `<HMAC-TOKEN>` with a valid HMAC signature

## [2.4.1] - 2025-03-10
### Changed
- **Configuration:** Updated `globalextensions` in `config.toml` to `["*"]`, allowing all file types globally for uploads. This change simplifies the configuration by removing the need to specify individual file extensions.

## [2.4.0] - 2025-02-20
### Added
- **Pre-Caching Support:** Introduced pre-caching of storage paths to improve access speeds.
- **ISO Container Management:** Added functionality to create and mount ISO containers for specialized storage needs.
- **Thumbnail Concurrency Parameter:** Users can now set the level of concurrency for thumbnail generation to optimize performance.

### Changed
- **Configuration Options:** Updated `config.toml` to include new settings for pre-caching and ISO management.
- **Documentation:** Enhanced `README.MD` with detailed instructions on new features and best practices.

### Fixed
- **Bug Fixes:** Resolved minor issues related to file versioning and deduplication processes.

## [2.3.1] - 2025-01-15
### Changed
- **Configuration:** Updated `globalextensions` in `config.toml` to `["*"]`, allowing all file types globally for uploads. This change simplifies the configuration by removing the need to specify individual file extensions.

## [2.3.0] - 2024-12-28
### Changed
- **Server:** Replaced the hardcoded temporary upload directory `/tmp/uploads` with a configurable `TempPath` parameter in `config.toml`. Ensure to set `tempPath` in your configuration file accordingly.

## [2.2.2] - 2024-12-27
### Bug Fixes
- Resolved issue where temporary `.tmp` files caused "Unsupported file type" warnings by adjusting MIME type detection to use the final file extension.

### Enhancements
- Improved logging for file extension and MIME type during uploads.

## [2.2.1] - 2024-12-27
### Enhancements
- Added detailed logging for file extensions and MIME types during file uploads to assist in diagnosing unsupported file type issues.

### Configuration
- Updated `config.toml` to ensure necessary file extensions are allowed for uploads.

---
## Changelog

For a detailed list of changes, please refer to the [Changelog](./Changelog.md).