
# HMAC File Server

The HMAC File Server is a lightweight, secure file-handling server that uses HMAC-based authentication. It offers configurable features like file versioning, rate-limiting, auto-banning, and Prometheus metrics for monitoring.

## Features
- **HMAC-based authentication** for secure file handling.
- **File versioning**: Automatically version your files.
- **Rate-limiting and auto-banning**: Protects the server from abuse.
- **Prometheus metrics**: Monitor server performance.
- **Configurable logging**: Log to a file with support for log rotation.
  
## Download

To download the latest version of the HMAC File Server, use the following commands:

```bash
git clone https://github.com/PlusOne/hmac-file-server.git
cd hmac-file-server
go build -o hmac-file-server main.go
```

## Configuration

Create a `config.toml` file in the root directory of the project with the following settings:

```toml
# Server Configuration
ListenPort = ":8080"
UnixSocket = false
Secret = "your-secret-key"
StoreDir = "/mnt/storage/hmac-file-server/"
UploadSubDir = "upload"
LogLevel = "debug"
LogFile = "/var/log/hmac-file-server.log"

# Versioning
EnableVersioning = true
VersioningDirectory = "/mnt/storage/hmac-file-server/versions/"
MaxVersions = 2
VersioningStrategy = "timestamp"

# Retry settings
MaxRetries = 5
RetryDelay = 2
EnableGetRetries = true

# File upload settings
MaxUploadSize = 1073741824  # 1 GB in bytes
BufferSize = 65536          # 64 KB in bytes
MinFreeSpaceThreshold = 104857600  # 100 MB

# Rate limiting and banning
BlockAfterFails = 5
BlockDuration = 300
AutoUnban = true
AutoBanTime = 600

# File deletion settings
DeleteFiles = true
DeleteFilesAfterPeriod = "1y"
DeleteFilesReport = true
DeleteFilesReportPath = "/home/hmac-file-server/deleted_files.log"

# CPU usage
NumCores = "auto"

# HMAC re-asking
ReaskSecretEnabled = true
ReaskSecretInterval = "1h"

# Metrics
MetricsEnabled = true
MetricsPort = ":9090"
```

### Configuration Options

- **ListenPort**: The port on which the server listens for incoming HTTP requests.
- **UnixSocket**: Set to `true` to use a Unix socket instead of TCP.
- **Secret**: The HMAC secret used for authentication.
- **StoreDir**: The directory where files are stored.
- **UploadSubDir**: The subdirectory for uploads.
- **LogLevel**: Logging verbosity (`debug`, `info`, `warn`, etc.).
- **LogFile**: Path to the log file. If empty, logs will output to stdout.
- **Versioning**: Enable versioning and set the maximum number of versions.

## Usage

Run the server after configuring:

```bash
./hmac-file-server -config ./config.toml
```

### File Upload Example

To upload a file, use the following `curl` command:

```bash
curl -X PUT -T filename.txt http://localhost:8080/upload/filename.txt
```

### Prometheus Metrics

If metrics are enabled, you can scrape them from the `/metrics` endpoint:

```bash
curl http://localhost:9090/metrics
```

This will return standard Prometheus metrics with the `hmac_` prefix for HMAC-specific metrics.

## Logging

Logging can be configured via `config.toml`. You can specify a log file path using the `LogFile` option. By default, logs are written to `stdout`.

For log rotation, it's recommended to configure `logrotate`:

1. Create a logrotate config file (e.g., `/etc/logrotate.d/hmac-file-server`):
    ```bash
    /var/log/hmac-file-server.log {
        daily
        rotate 7
        compress
        delaycompress
        missingok
        notifempty
        copytruncate
    }
    ```

This setup will rotate logs daily, keep the last 7 days' worth of logs, and compress old logs.
