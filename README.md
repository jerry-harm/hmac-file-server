
# HMAC File Server

## Overview

The HMAC File Server is a secure file handling server that utilizes HMAC for authentication. It allows you to upload and manage files securely while providing metrics for monitoring.

## Features

- **HMAC Authentication**: Ensures the integrity and authenticity of uploaded files using HMAC.
- **Secure File Uploads and Downloads**: Facilitates secure uploading and downloading of files.
- **Prometheus Metrics Support**: Exposes metrics for monitoring using Prometheus.
- **Rate Limiting and Banning**: Configurable options to prevent abuse by limiting failed attempts.
- **Automatic File Deletion**: Automatically deletes files after a specified period.
- **Dynamic Configuration**: Easily adjustable settings via a TOML configuration file.
- **CORS Support**: Configurable Cross-Origin Resource Sharing (CORS) headers for API access.

## Configuration

The server is configured via a `config.toml` file. Below are the key configuration options:

```toml
# Server listening port for TCP (used if UnixSocket is false)
ListenPort = ":8080"

# Use Unix socket (true or false)
UnixSocket = false

# Path to the Unix socket (used if UnixSocket is true)
# UnixSocketPath = "/home/hmac-file-server/hmac.sock"

# Secret key for HMAC authentication
Secret = "your-secret-key"

# Directories for storing files
StoreDir = "/mnt/storage/hmac-file-server/"
UploadSubDir = "upload"

# Logging level ("debug", "info", "warn", "error")
LogLevel = "info"

# Retry settings
MaxRetries = 5
RetryDelay = 2
EnableGetRetries = true

# Rate limiting and banning
BlockAfterFails = 5
BlockDuration = 300            # Duration in seconds to block after exceeding failed attempts
AutoUnban = true               # Automatically unban after block duration
AutoBanTime = 600              # Duration in seconds for auto-ban

# File deletion settings
DeleteFiles = true
DeleteFilesAfterPeriod = "1y" # Can be in days (d), months (m), or years (y)
DeleteFilesReport = true
DeleteFilesReportPath = "/home/hmac-file-server/deleted_files.log"

# CPU core settings
NumCores = "auto"              # Set to "auto" to use all available cores or a specific number like "2", "4", etc.

# Buffer settings
BufferEnabled = true           # Enable or disable the buffer pool for read/write operations
BufferSize = 65536             # Size of the buffer in bytes (e.g., 64 KB)

# HMAC Secret Re-ask Configuration
ReaskSecretEnabled = true                    # Enable or disable periodic secret reasking
ReaskSecretInterval = "24h"                   # Interval for reasking the secret (e.g., "24h" for 24 hours)

# Monitoring Configuration
MetricsEnabled = true                         # Enable Prometheus metrics
MetricsPort = ":9090"                         # Port for metrics endpoint
```

### Explanation of Configuration Options

- **ListenPort**: The TCP port on which the server listens for file handling requests. Default is `:8080`.
- **UnixSocket**: If set to `true`, the server will use a Unix socket instead of a TCP port.
- **UnixSocketPath**: The file system path for the Unix socket. Only applicable if `UnixSocket` is `true`.
- **Secret**: The secret key used for HMAC authentication.
- **StoreDir**: Directory where uploaded files are stored.
- **UploadSubDir**: Subdirectory within `StoreDir` for uploads.
- **LogLevel**: Logging verbosity level (`debug`, `info`, `warn`, `error`).
- **MaxRetries**: Maximum number of retry attempts for failed operations.
- **RetryDelay**: Delay between retry attempts in seconds.
- **EnableGetRetries**: Enable retries for GET requests.
- **BlockAfterFails**: Number of failed attempts after which the path is banned.
- **BlockDuration**: Duration (in seconds) to block a path after exceeding failed attempts.
- **AutoUnban**: Automatically unban a path after the block duration expires.
- **AutoBanTime**: Duration (in seconds) for which a path remains banned.
- **DeleteFiles**: Enable automatic deletion of files after a certain period.
- **DeleteFilesAfterPeriod**: Time period after which files are deleted (`d` for days, `m` for months, `y` for years).
- **DeleteFilesReport**: Enable logging of deleted files.
- **DeleteFilesReportPath**: File path where deletion logs are stored.
- **NumCores**: Number of CPU cores to utilize (`auto` to use all available cores).
- **BufferEnabled**: Enable or disable the buffer pool for read/write operations.
- **BufferSize**: Size of the buffer in bytes.
- **ReaskSecretEnabled**: Enable periodic reasking for the HMAC secret.
- **ReaskSecretInterval**: Interval for reasking the HMAC secret.
- **MetricsEnabled**: Enable Prometheus metrics collection.
- **MetricsPort**: Port on which the metrics server listens (default `:9090`).

## Running the Server

To run the HMAC File Server, use the following command:

```bash
./hmac-file-server --config=/path/to/config.toml
```

Ensure that your `config.toml` is correctly configured with the desired settings before running the server.

## Accessing Metrics

If **Metrics Support** is enabled in your configuration (`MetricsEnabled = true`), the server exposes metrics for Prometheus at the following endpoint:

```
http://<your-server-ip>:9090/metrics
```

### Available Metrics

- **Go Runtime Metrics**: Includes garbage collection stats, memory usage, goroutines, and more.
- **Custom Metrics**: Number of active goroutines specific to the HMAC File Server.

You can visualize these metrics using monitoring tools like **Grafana** by setting up Prometheus as a data source.

## File Operations

### Uploading a File

To upload a file, send a `PUT` request to the server:

```bash
curl -X PUT --data-binary @/path/to/your/file http://<your-server-ip>:8080/upload/<your-file>
```

### Downloading a File

To download a file, send a `GET` request:

```bash
curl -O http://<your-server-ip>:8080/upload/<your-file>
```

## Rate Limiting and Banning

The server can automatically ban paths that exceed a specified number of failed attempts. This helps prevent abuse and ensures the server remains secure.

### Configuration Options

- **BlockAfterFails**: Number of failed attempts before banning.
- **BlockDuration**: Duration for which the path remains banned.
- **AutoUnban**: Automatically unban after the block duration.

## Automatic File Deletion

The server can be configured to automatically delete files after a specified period, helping manage storage effectively.

### Configuration Options

- **DeleteFiles**: Enable or disable automatic file deletion.
- **DeleteFilesAfterPeriod**: Time period after which files are deleted.
- **DeleteFilesReport**: Enable logging of deleted files.
- **DeleteFilesReportPath**: Path to the log file for deletions.

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## Contact

For any questions or support, please contact [your-email@example.com](mailto:your-email@example.com).
