
# HMAC File Server

The HMAC File Server is a secure, high-performance HTTP server for file uploads and downloads. It uses HMAC (Hash-based Message Authentication Code) to ensure file integrity and includes features like versioning, rate limiting, automatic file deletion, and Prometheus metrics.

## Features

- **HMAC-based security** for file uploads/downloads.
- **File versioning** with configurable strategies and limits.
- **Rate limiting** and **auto-banning** to prevent abuse.
- **Prometheus integration** for server and request metrics.
- **CORS support** for cross-origin file handling.
- **Configurable CPU core usage** for optimal performance.
- **Automatic file deletion** with reporting.
- **Unix socket and TCP support** for flexible communication.
- **Detailed logging** to file and console.
- **Graceful shutdown** on system signals.

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Versioning](#versioning)
- [Metrics](#metrics)
- [Logging](#logging)
- [Contributing](#contributing)
- [License](#license)

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/PlusOne/hmac-file-server.git
   cd hmac-file-server
   ```

2. **Build the binary**:

   ```bash
   go build -o hmac-file-server .
   ```

3. **Configure the server**:

   Create a `config.toml` file or use the default one provided in the repository. See the [Configuration](#configuration) section for details.

4. **Run the server**:

   ```bash
   ./hmac-file-server -config config.toml
   ```

## Configuration

The configuration is managed via a `config.toml` file. Below is an example configuration file with explanations:

```toml
ListenPort = ":8080"
UnixSocket = false
UnixSocketPath = "/tmp/hmac-file-server.sock"

Secret = "your-secret-here"
StoreDir = "/mnt/storage/hmac-file-server"
UploadSubDir = "uploads"

LogLevel = "info"
LogFile = "/var/log/hmac-file-server.log"

EnableVersioning = true
VersioningDirectory = "/mnt/storage/hmac-file-server/versions/"
MaxVersions = 5
VersioningStrategy = "timestamp"

MaxRetries = 5
RetryDelay = 2
EnableGetRetries = true
BlockAfterFails = 3
BlockDuration = 3600
AutoUnban = true
AutoBanTime = 7200

DeleteFiles = true
DeleteFilesAfterPeriod = "24h"
DeleteFilesReport = true
DeleteFilesReportPath = "/var/log/hmac-file-server/deleted_files.log"

NumCores = "auto"
ReaskSecretEnabled = true
ReaskSecretInterval = "24h"

MetricsEnabled = true
MetricsPort = ":9090"

MinFreeSpaceThreshold = 104857600  # 100MB
MaxUploadSize = 1073741824         # 1GB
BufferSize = 65536                 # 64KB
```

### Key Configuration Options

- **ListenPort**: Port to listen on (default `:8080`).
- **UnixSocket**: Use Unix socket instead of TCP (set to `true` or `false`).
- **Secret**: HMAC secret key for secure file operations.
- **StoreDir**: Directory where uploaded files are stored.
- **EnableVersioning**: Enable versioning of uploaded files.
- **MaxRetries**: Maximum number of retries before banning.
- **MetricsEnabled**: Enable Prometheus metrics on a separate port.
- **MaxUploadSize**: Maximum allowed file upload size.

## Usage

### Command Line Options

- `-config` : Path to the configuration file. Example:

  ```bash
  ./hmac-file-server -config ./config.toml
  ```

- `-help`: Display help message.
  
  ```bash
  ./hmac-file-server -help
  ```

- `-version`: Display the current version.

  ```bash
  ./hmac-file-server -version
  ```

### File Upload

Upload files using `PUT` requests:

```bash
curl -X PUT --data-binary @/path/to/your/file http://your-server:8080/uploads/filename
```

### File Download

Download files using `GET` requests:

```bash
curl -O http://your-server:8080/uploads/filename
```

## Versioning

If **versioning** is enabled in the configuration, files are stored with versions based on the chosen strategy (e.g., timestamp). You can set the `MaxVersions` parameter to limit the number of versions to retain per file.

## Metrics

The server supports **Prometheus metrics** if enabled in the configuration. Metrics can be accessed at the `/metrics` endpoint, served on a configurable port.

Available metrics:
- **hmac_file_server_total_uploads**: Total number of file uploads.
- **hmac_file_server_total_downloads**: Total number of file downloads.
- **hmac_file_server_upload_duration_seconds**: Duration of file uploads.
- **hmac_file_server_goroutines**: Number of active goroutines.

## Logging

The server logs events such as file uploads, downloads, errors, and bans. Logs are written to both the console and the specified log file in the configuration (`LogFile`).

Log levels can be configured using the `LogLevel` option. Available levels: `debug`, `info`, `warn`, `error`.

## Contributing

Feel free to contribute to this project by submitting issues or pull requests. Follow these steps for contributions:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -m "Add a new feature"`).
4. Push to your branch (`git push origin feature-branch`).
5. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
