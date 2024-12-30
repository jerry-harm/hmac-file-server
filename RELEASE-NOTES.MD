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
FileTTL = "1y"
FileTTLEnabled = true  # Enable or disable file TTL
MinFreeBytes = "100MB"
AutoAdjustWorkers = true  # Enable auto-adjustment for worker scaling
NetworkEvents = false     # Disable logging and tracking of network-related events
PIDFilePath = "./hmac_file_server.pid"  # Path to PID file
Precaching = true  # Enable pre-caching of storage paths
TempPath = "/tmp/uploads"  # Configurable temporary upload directory

[deduplication]
enabled = true
directory = "/mnt/nfs_vol01/hmac-storage/deduplication/"

[iso]
Enabled = false
Size = "2TB"
MountPoint = "/mnt/iso"
Charset = "utf-8"

[thumbnails]
enabled = true
directory = "/mnt/nfs_vol01/hmac-file-server/thumbnails/"
size = "200x200"
concurrency = 5
thumbnailintervalscan = "24h"

[iso]
enabled = false
size = "1TB"
mountpoint = "/mnt/nfs_vol01/hmac-file-server/iso/"
charset = "utf-8"

[timeouts]
ReadTimeout = "480s"
WriteTimeout = "480s"
IdleTimeout = "65s"  # nginx/apache2 keep-alive 60s

[security]
Secret = "changeme"

[versioning]
EnableVersioning = false
MaxVersions = 1

[uploads]
ResumableUploadsEnabled = true
ChunkedUploadsEnabled = true
ChunkSize = "64MB"
AllowedExtensions = [".txt", ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".svg", ".webp", ".wav", ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".mpeg", ".mpg", ".m4v", ".3gp", ".3g2", ".mp3", ".ogg"]

[downloads]
ResumableDownloadsEnabled = true
ChunkedDownloadsEnabled = true
ChunkSize = "64MB"

[clamav]
ClamAVEnabled = false
ClamAVSocket = "/var/run/clamav/clamd.ctl"
NumScanWorkers = 2
ScanFileExtensions = [".exe", ".dll", ".bin", ".com", ".bat", ".sh", ".php", ".js"]

[redis]
RedisEnabled = false
RedisAddr = "localhost:6379"
RedisPassword = ""
RedisDBIndex = 0
RedisHealthCheckInterval = "120s"

[workers]
NumWorkers = 4
UploadQueueSize = 5000

[file]
FileRevision = 1  # Revision number for file handling

[logging]
level = "info"
file = "/var/log/hmac-file-server.log"
max_size = 100
max_backups = 7
max_age = 30
compress = true
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
````

## [2.3.0] - 2024-12-28

### Changed
- **Server:** Replaced the hardcoded temporary upload directory `/tmp/uploads` with a configurable `TempPath` parameter in `config.toml`. Ensure to set `tempPath` in your configuration file accordingly.

#### Version 2.2.1 - 2024-12-27

- **Enhancements:**
  - Added detailed logging for file extensions and MIME types during file uploads to assist in diagnosing unsupported file type issues.
  
- **Configuration:**
  - Updated `config.toml` to ensure necessary file extensions are allowed for uploads.

#### Version 2.2.2 - 2024-12-27

- **Bug Fixes:**
  - Resolved issue where temporary `.tmp` files caused "Unsupported file type" warnings by adjusting MIME type detection to use the final file extension.
  
- **Enhancements:**
  - Improved logging for file extension and MIME type during uploads.

### Summary of Changes

1. **Added Log Message Limitation:**
   - Implemented `logMessages = logMessages[1:]` to remove the oldest log message once the `logMessages` slice exceeds 1000 entries, preventing unbounded memory growth.

---

### Additional Files

2024-12-30 endpoint /thumbnails

No changes are required for the other files (`RELEASE-NOTES.MD`, `README.MD`, `config.toml`).

## [2.3.1] - 2025-01-15
- Added metrics for deduplication and ISO container operations to improve observability.
- Additional detail: Thumbnails now support a "concurrency" configuration parameter for parallel image processing.

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

### Summary of Changes
1. **Pre-Caching:** Improved performance by allowing the server to pre-cache frequently accessed storage paths.
2. **ISO Management:** Enabled the creation and mounting of ISO containers for better filesystem management.
3. **Thumbnail Generation:** Added a concurrency setting to allow parallel processing of image thumbnails, speeding up the generation process.

## [2.4.1] - 2025-03-10

### Changed
- **Configuration:** Updated `globalextensions` in `config.toml` to `["*"]`, allowing all file types globally for uploads. This change simplifies the configuration by removing the need to specify individual file extensions.

## Release Notes

**Release Date:** December 24, 2024 (Happy Holidays!)

## Overview

We are thrilled to announce the release of **hmac-file-server v2.4-stable**. This version builds upon our previous releases with significant enhancements, new features, and crucial bug fixes aimed at boosting the performance, security, and usability of the HMAC File Server.

### **Attention:**
Due to a critical deduplication issue identified in v2.1-stable, which may impact file handling under specific configurations, we recommend users skip v2.1-stable and upgrade directly to v2.4-stable from earlier stable versions.

## New Features

### 1. **Thumbnail Creation**
- **Automated Image Thumbnails:** Generate image thumbnails for uploaded files to provide quick previews and enhance user experience.
- **Scheduled Generation:** Thumbnails are created at configurable intervals to optimize server performance.
- **Configuration:**
  ```toml
  [thumbnails]
  enabled = true
  directory = "/path/to/hmac-file-server/thumbnails/"
  size = "200x200"
  thumbnailintervalscan = "1h"  # Interval for scheduled thumbnail generation
  ```

### 2. **ClamAV Integration**
- **Robust Malware Scanning:** Integrated ClamAV for scanning uploaded files, ensuring file integrity and security.
- **Configurable Scan Workers:** Optimize performance with a configurable number of scan workers.
- **Configuration:**
  ```toml
  [clamav]
  clamavenabled = true
  clamavsocket = "/path/to/clamav/clamd.ctl"  # Path to ClamAV socket
  numscanworkers = 4  # Number of concurrent scan workers
  scanfileextensions = [
      ".exe", ".dll", ".bin", ".com", ".bat",
      ".sh", ".php", ".js"
  ]
  ```

### 3. **Redis Support**
- **Enhanced Caching and Session Management:** Utilize Redis for efficient caching of file metadata and managing application states.
- **High-Load Scalability:** Supports high-load environments with optimized Redis configurations.
- **Configuration:**
  ```toml
  [redis]
  redisenabled = true
  redisdbindex = 0
  redisaddr = "localhost:6379"  # Redis server address
  redispassword = ""            # Redis password if required
  redishealthcheckinterval = "120s"  # Interval for Redis health checks
  ```

### 4. **Enhanced Configuration Management**
- **Expanded Customization Options:** More configuration options for server behavior, including auto-adjusting worker pools and network event logging.
- **Improved Configuration Structure:** Streamlined configuration keys for better clarity and maintainability.
- **Configuration:**
  ```toml
  [server]
  autoadjustworkers = true  # Automatically adjust worker threads based on load
  networkevents = false     # Enable detailed network event logging
  precaching = true         # Pre-cache file structures on startup for faster access
  ```

### 5. **Improved Logging**
- **JSON-Formatted Logs:** Optional support for JSON-formatted logs for better integration with log management systems.
- **Configurable Log Output:** Direct logs to files with log rotation and compression.
- **Configuration:**
  ```toml
  [server]
  loglevel = "debug"  # Logging level: "debug", "info", "warn", "error"
  logfile = "/path/to/hmac-file-server.log"  # Path to log file; leave empty to use stdout

  [server]
  loggingjson = false  # Set to true for JSON-formatted logs
  ```

## Enhancements

- **Graceful Shutdown:** Ensures data integrity during server restarts by handling OS signals and performing necessary cleanup.
- **Auto-Adjusting Worker Pools:** Optimizes the number of worker threads dynamically based on system resources to maintain optimal performance.
- **Extended Timeouts:** Customizable connection timeouts to handle long-running requests and prevent resource exhaustion.
- **Configuration:**
  ```toml
  [timeouts]
  readtimeout = "3600s"    # Maximum time to read a request (1 hour)
  writetimeout = "3600s"   # Maximum time to write a response (1 hour)
  idletimeout = "3600s"    # Maximum keep-alive time for idle connections (1 hour)
  ```

## Bug Fixes

- **Deduplication Issue Resolved:** Fixed the critical deduplication bug from v2.1-stable to ensure reliable file handling under all configurations.
- **Syntax Cleanup:** Streamlined codebase by removing unused parameters and functions to enhance code maintainability.
- **Improved Error Handling:** Enhanced startup checks for ClamAV and Redis to provide clearer error messages and prevent server crashes.
- **Configuration Validation:** Added comprehensive configuration validation to catch misconfigurations early during server startup.

## Performance Improvements

- **Optimized File Handling:** Enhanced processing speeds for uploads and downloads, reducing latency and improving user experience.
- **Enhanced Caching Mechanisms:** Improved caching strategies using Redis and in-memory caches to reduce load times and server strain.
- **Thumbnail Generation Optimization:** Scheduled thumbnail generation minimizes performance hits during peak usage times.

## Security Enhancements

- **ClamAV and Redis Secure Integration:** Implemented secure connections and enhanced virus scanning protocols to safeguard against malicious files.
- **HMAC Secret Management:** Enforced the use of strong, unique HMAC secrets to ensure secure authentication and request signing.

## Configuration Changes

- **Removed Duplicate `[iso]` Block:** Consolidated ISO configuration into a single `[iso]` section to prevent configuration conflicts.
- **Updated Configuration Keys:** Renamed `scanInterval` to `thumbnailintervalscan` in the `[thumbnails]` section to align with the codebase.
- **Deprecated Options Removed:** Streamlined configuration by removing outdated or unnecessary options, simplifying the setup process.
- **Example Configuration Updated:** Provided an updated `config.toml` example reflecting the latest configuration structure and keys.

## Known Issues

- **Auto-Adjusting Delays:** Potential delays in worker pool adjustments under extreme load conditions. Monitoring is recommended to ensure optimal performance.
- **JSON Logs Integration:** JSON-formatted logs may require additional tools or configurations for seamless integration with existing log management systems.
- **Thumbnail Generation Overhead:** In environments with high upload rates of large images, thumbnail generation may introduce additional CPU load. Adjust `thumbnailintervalscan` as needed.

## Upgrade Instructions

1. **Backup Current Configuration:**
   ```bash
   cp ./config.toml ./config.toml.backup
   ```

2. **Pull the Latest Version:**
   ```bash
   git pull origin v2.4-stable
   ```

3. **Update Dependencies:**
   ```bash
   go mod tidy
   ```

4. **Review and Merge Configuration Changes:**
   - Compare your existing `config.toml` with the example provided in the [Example `config.toml`](#example-configtoml) section.
   - Update configuration keys and values as necessary, especially ensuring that `thumbnailintervalscan` is used instead of `scanInterval`.

5. **Build the Server:**
   ```bash
   go build -o hmac-file-server main.go
   ```

6. **Restart the Server:**
   ```bash
   systemctl restart hmac-file-server
   ```
   - **OR**
   ```bash
   ./hmac-file-server -config ./config.toml
   ```

## Acknowledgments

Thank you to our contributors and the community for their invaluable feedback and support. Special thanks to the developers of [[Thomas Leister's prosody-filer](https://github.com/ThomasLeister/prosody-filer)](https://github.com/ThomasLeister/prosody-filer) for inspiring many of our core features.

## Support

For support, please open an issue on our [[GitHub repository](https://github.com/PlusOne/hmac-file-server/issues)](https://github.com/PlusOne/hmac-file-server/issues).

---

Enjoy the enhanced features and stability of **hmac-file-server v2.4-stable**, and thank you for choosing our solution!
