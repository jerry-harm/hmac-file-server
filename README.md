
# HMAC File Server

## Overview
The HMAC File Server is a secure file handling server that uses HMAC authentication for uploads. It supports Redis caching and can fall back to a PostgreSQL or MySQL database.

## Configuration (config.toml)
Below is a detailed explanation of each configuration option in the `config.toml` file.

### Server Settings
- **ListenPort**: The port on which the server will listen. (Example: `:8080`)
- **UnixSocket**: Whether to use a Unix socket instead of a TCP socket. (Set to `true` or `false`)
- **Secret**: The HMAC secret key used to sign uploads.
- **StoreDir**: The directory where uploaded files will be stored.
- **UploadSubDir**: The subdirectory under `StoreDir` where uploads will be saved.
- **LogLevel**: The logging level for the server (`info`, `warn`, `error`).
- **LogFile**: Path to the log file. Leave empty to log to `stdout`.
- **MaxRetries**: Maximum number of retries for failed uploads.
- **RetryDelay**: Delay (in seconds) between retries.
- **MetricsEnabled**: Enable Prometheus metrics. (Set to `true` or `false`)
- **MetricsPort**: Port for Prometheus metrics server.
- **ChunkSize**: Size of each chunk during a chunked upload, in bytes.
- **UploadMaxSize**: Maximum size of uploads allowed, in bytes.
- **MaxBytesPerSecond**: Maximum upload rate in bytes per second (for throttling uploads).

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
# Example of config.toml
ListenPort = ":8080"
UnixSocket = false
Secret = "your_secret_here"
StoreDir = "/path/to/store/files"
UploadSubDir = "upload"
LogLevel = "info"
LogFile = "/var/log/hmac-file-server.log"
MaxRetries = 5
RetryDelay = 2
MetricsEnabled = true
MetricsPort = ":9090"
ChunkSize = 65536
UploadMaxSize = 1073741824  # 1 GB
MaxBytesPerSecond = 1048576  # 1 MB/s

# Redis Configuration
RedisAddr = "localhost:6379"
RedisPassword = ""
RedisDB = 0

# Fallback Configuration
FallbackEnabled = false
FallbackDBType = "postgres"
FallbackDBHost = "localhost"
FallbackDBUser = "your_db_user"
FallbackDBPassword = "your_db_password"
FallbackDBName = "your_db_name"
```

## Features
- Secure file handling with HMAC authentication
- Support for Redis caching
- Fallback to PostgreSQL or MySQL database
- Prometheus metrics for monitoring

## Getting Started
1. Configure the `config.toml` file according to your setup.
2. Start the server and begin uploading files.

## License
This project is licensed under the MIT License.
