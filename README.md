
# HMAC File Server

## Overview

The **HMAC File Server** is a secure file handling server that supports HMAC-based authentication for uploads and downloads. It also integrates optional Redis caching, fallback databases (PostgreSQL/MySQL), rate limiting, chunked uploads, and Prometheus metrics for monitoring.

## Features

- HMAC-based secure uploads and downloads.
- Supports Redis caching and fallback to PostgreSQL/MySQL databases.
- Rate limiting and chunked uploads.
- Prometheus metrics for monitoring upload performance.
- Graceful shutdown handling.
- Customizable via a configuration file.

## Getting Started

1. Clone the repository.
2. Build the project using Go.
3. Create a `config.toml` file and set the appropriate values.

## Configuration (config.toml)

Below is a detailed explanation of each configuration option in the `config.toml` file.

### Server Settings

- **ListenPort**: The port on which the server will listen. (Example: `:8080`)
- **UnixSocket**: Whether to use a Unix socket instead of a TCP socket. (Set to `true` or `false`)
- **Secret**: The HMAC secret key used to sign uploads.
- **StoreDir**: The directory where uploaded files will be stored.
- **UploadSubDir**: Subdirectory under `StoreDir` where uploads will be saved.
- **LogLevel**: Logging level for the server (`info`, `warn`, `error`).
- **LogFile**: Path to the log file. Leave empty to log to `stdout`.
- **MaxRetries**: Maximum number of retries for failed uploads.
- **RetryDelay**: Delay (in seconds) between retries.
- **MetricsEnabled**: Enable Prometheus metrics. (Set to `true` or `false`)
- **MetricsPort**: Port for Prometheus metrics server.
- **ChunkSize**: Size of each chunk during a chunked upload, in bytes.
- **UploadMaxSize**: Maximum size of uploads allowed, in bytes (optional).
- **MaxBytesPerSecond**: Maximum upload rate in bytes per second (for rate limiting).

### Redis Configuration

- **RedisAddr**: Address of the Redis server (leave blank if not using Redis).
- **RedisPassword**: Password for Redis (leave blank if no password is required).
- **RedisDB**: Redis database number.

### Fallback Configuration

- **FallbackEnabled**: Enable fallback to a database if Redis is unavailable.
- **FallbackDBType**: Type of the fallback database (`postgres` or `mysql`).
- **FallbackDBHost**: Hostname of the fallback database.
- **FallbackDBUser**: Username for the fallback database.
- **FallbackDBPassword**: Password for the fallback database.
- **FallbackDBName**: Name of the fallback database.

### Example Configuration

```toml
# Server settings
ListenPort = ":8080"
UnixSocket = false
Secret = "horse-fish-brain-secret"
StoreDir = "/mnt/storage/hmac-file-server/"
UploadSubDir = "upload"
LogLevel = "info"
LogFile = "/var/log/hmac-file-server.log"
MaxRetries = 5
RetryDelay = 2
MetricsEnabled = true
MetricsPort = ":9090"
ChunkSize = 65536
UploadMaxSize = 1073741824  # 1GB
MaxBytesPerSecond = 1048576 # 1MB/s

# Redis configuration
RedisAddr = "localhost:6379"
RedisPassword = ""
RedisDB = 0

# Fallback configuration
FallbackEnabled = true
FallbackDBType = "postgres"
FallbackDBHost = "localhost"
FallbackDBUser = "your_db_user"
FallbackDBPassword = "your_db_password"
FallbackDBName = "your_db_name"
```

## Running the Server

To start the server:

```bash
./hmac-file-server -config ./config.toml
```

Make sure that the config file is located in the appropriate path, and that all required services (Redis, PostgreSQL/MySQL) are up and running if they are enabled.

## Monitoring with Prometheus

If `MetricsEnabled` is set to `true`, the server will expose Prometheus metrics on the specified `MetricsPort`. You can monitor upload rates, errors, and more.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
