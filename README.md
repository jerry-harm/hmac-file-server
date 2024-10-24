# HMAC File Server

## Overview

The **HMAC File Server** is a secure and scalable solution for file uploads and downloads, protected by HMAC (Hash-based Message Authentication Code). It supports chunked file uploads, rate limiting, Prometheus metrics, and optional Redis or fallback database (PostgreSQL/MySQL) for session handling. 

This server ensures secure file transfers using a configurable HMAC key and offers easy monitoring through Prometheus metrics. It is designed for efficient performance with support for both memory and CPU usage tracking.

## Features

- **Secure File Uploads and Downloads** using HMAC
- **Chunked File Uploads** with optional Redis or fallback database support
- **Rate Limiting** for uploads
- **Prometheus Metrics** for monitoring upload/download activity, CPU, memory, and more
- **Graceful Shutdown** to ensure no data loss during termination
- **PostgreSQL/MySQL Fallback** for Redis session handling

![image](https://github.com/user-attachments/assets/2c32528d-2169-47c9-9d5b-bd3f77f26c53)

## Configuration

The configuration for the HMAC File Server is managed through a TOML file. Below is an example configuration:

```toml
# Server settings
ListenPort = ":8080"                   # Port for the file server to listen on
UnixSocket = false                     # Use Unix sockets if true, otherwise TCP
Secret = "a-horse-is-a-horse-even-is-a-jet"    # HMAC secret for securing uploads
StoreDir = "/mnt/storage/hmac-file-server/"  # Directory for storing uploaded files
UploadSubDir = "upload"                # Subdirectory for uploads
LogLevel = "info"                      # Logging level: "debug", "info", "warn", "error"
LogFile = "/var/log/hmac-file-server.log"  # Log file path
MaxRetries = 5                         # Maximum number of retries for failed uploads
RetryDelay = 2                         # Delay in seconds between retries

# Metrics configuration
MetricsEnabled = true                  # Enable Prometheus metrics
MetricsPort = ":9090"                  # Port for Prometheus metrics server

# Upload settings
ChunkSize = 65536                      # Size of each chunk for chunked uploads (in bytes)
UploadMaxSize = 1073741824             # Maximum upload size (1 GB in bytes)
MaxBytesPerSecond = 1048576            # Throttle upload speed to 1 MB/s

# Redis configuration (optional)
RedisAddr = "localhost:6379"           # Redis server address (leave blank if not using Redis)
RedisPassword = ""                     # Redis password (leave blank if no password is required)
RedisDB = 0                            # Redis database number

# Fallback database configuration (optional)
FallbackEnabled = false                # Enable fallback to a database if Redis is unavailable
FallbackDBType = "postgres"            # Fallback database type ("postgres" or "mysql")
FallbackDBHost = "localhost"           # Fallback database host
FallbackDBUser = "your_db_user"        # Fallback database username
FallbackDBPassword = "your_db_password" # Fallback database password
FallbackDBName = "your_db_name"        # Fallback database name

# Graceful shutdown settings
GracefulShutdownTimeout = 30           # Timeout for graceful shutdowns (in seconds)
```

## Running the Server

1. Download and configure the `config.toml` file for the server.
2. Run the server using the following command:
   ```bash
   ./hmac-file-server -config /path/to/config.toml
   ```

3. The server will start on the configured port (e.g., `:8080`), and metrics will be available on the Prometheus metrics server port (e.g., `:9090`).

## Prometheus Metrics

The HMAC File Server exposes several key metrics through Prometheus:

- **File Upload Duration** (`file_server_upload_duration_seconds`)
- **File Download Duration** (`file_server_download_duration_seconds`)
- **Upload/Download Errors** (`file_server_upload_errors_total`, `file_server_download_errors_total`)
- **Memory and CPU Usage** (`memory_usage_bytes`, `cpu_usage_percent`)
- **Active Connections** (`active_connections_total`)
- **Goroutines Count** (`goroutines_count`)
- **Total Requests** (`http_requests_total`, labeled by method and path)

## Logging

Logging can be directed to a file or the console. The logging level can be set to `debug`, `info`, `warn`, or `error` in the `config.toml`.

- **File Logging:** Specify the log file path using the `LogFile` configuration option.
- **Console Logging:** If no file is specified, logs will be printed to the console.

## Graceful Shutdown

To gracefully shut down the server:

1. Send a SIGINT or SIGTERM signal:
   ```bash
   kill -SIGINT <pid>
   ```
2. The server will finish handling active requests before shutting down.

## License

This project is licensed under the MIT License.
