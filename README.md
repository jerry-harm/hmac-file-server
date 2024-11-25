# HMAC File Server

HMAC File Server is a secure file handling server with HMAC authentication, ClamAV scanning, Redis integration, and Prometheus metrics.

## Configuration

The server is configured using a `config.toml` file. Below are all the configuration entries available:

### Server Configuration

- **ListenPort**: The port or Unix socket the server listens on.
  - Example: `":8080"`
- **UnixSocket**: Whether to use a Unix socket instead of a TCP port.
  - Example: `false`
- **Secret**: The secret key used for HMAC authentication.
  - Example: `"your-secret-key"`
- **StoreDir**: The directory where files are stored.
  - Example: `"/mnt/storage/hmac-file-server"`
- **UploadSubDir**: The subdirectory for uploads.
  - Example: `"upload"`
- **LogLevel**: The logging level.
  - Example: `"info"`
- **LogFile**: The file to write logs to.
  - Example: `"/var/log/hmac-file-server.log"`
- **MetricsEnabled**: Whether to enable Prometheus metrics.
  - Example: `true`
- **MetricsPort**: The port for the Prometheus metrics server.
  - Example: `"9090"`
- **FileTTL**: The time-to-live for files.
  - Example: `"168h0m0s"`
- **ResumableUploadsEnabled**: Whether to enable resumable uploads.
  - Example: `true`
- **ResumableDownloadsEnabled**: Whether to enable resumable downloads.
  - Example: `true`
- **EnableVersioning**: Whether to enable file versioning.
  - Example: `true`
- **MaxVersions**: The maximum number of file versions to keep.
  - Example: `5`
- **ChunkedUploadsEnabled**: Whether to enable chunked uploads.
  - Example: `true`
- **ChunkSize**: The size of chunks for chunked uploads.
  - Example: `1048576`
- **AllowedExtensions**: The allowed file extensions for uploads.
  - Example: `["png", "jpg", "jpeg", "gif", "txt", "pdf"]`

### Server Timeouts

- **ReadTimeout**: The read timeout for the server.
  - Example: `"2h"`
- **WriteTimeout**: The write timeout for the server.
  - Example: `"2h"`
- **IdleTimeout**: The idle timeout for the server.
  - Example: `"2h"`

### ClamAV Configuration

- **ClamAVEnabled**: Whether to enable ClamAV scanning.
  - Example: `true`
- **ClamAVSocket**: The Unix socket for ClamAV.
  - Example: `"/var/run/clamav/clamd.ctl"`
- **NumScanWorkers**: The number of ClamAV scan workers.
  - Example: `2`

### Redis Configuration

- **RedisEnabled**: Whether to enable Redis integration.
  - Example: `true`
- **RedisDBIndex**: The Redis database index.
  - Example: `0`
- **RedisAddr**: The address of the Redis server.
  - Example: `"localhost:6379"`
- **RedisPassword**: The password for the Redis server.
  - Example: `""`
- **RedisHealthCheckInterval**: The interval for Redis health checks.
  - Example: `"30s"`

### Workers and Connections

- **NumWorkers**: The number of upload workers.
  - Example: `2`
- **UploadQueueSize**: The size of the upload queue.
  - Example: `50`

## Example `config.toml`

```toml
# Server Configuration
ListenPort = ":8080"
UnixSocket = false
Secret = "your-secret-key"
StoreDir = "/mnt/storage/hmac-file-server"
UploadSubDir = "upload"
LogLevel = "info"
LogFile = "/var/log/hmac-file-server.log"
MetricsEnabled = true
MetricsPort = "9090"
FileTTL = "168h0m0s"
ResumableUploadsEnabled = true
ResumableDownloadsEnabled = true
EnableVersioning = true
MaxVersions = 5
ChunkedUploadsEnabled = true
ChunkSize = 1048576
AllowedExtensions = ["png", "jpg", "jpeg", "gif", "txt", "pdf"]

# Server timeouts
ReadTimeout = "2h"
WriteTimeout = "2h"
IdleTimeout = "2h"

# ClamAV Configuration
ClamAVEnabled = true
ClamAVSocket = "/var/run/clamav/clamd.ctl"
NumScanWorkers = 2

# Redis Configuration
RedisEnabled = true
RedisDBIndex = 0
RedisAddr = "localhost:6379"
RedisPassword = ""
RedisHealthCheckInterval = "30s"

# Workers and connections
NumWorkers = 2
UploadQueueSize = 50
