
# HMAC File Server

The HMAC File Server is designed to securely handle file uploads and downloads using HMAC (Hash-based Message Authentication Code) for verification. This server also includes support for retrying failed uploads, logging, and Prometheus metrics.

## Features
- **HMAC authentication** for secure file uploads.
- **Retry mechanism** for uploads with configurable retries and delays.
- **Prometheus metrics** for monitoring the server's performance.
- **Configurable** upload chunk size and server settings.
- **Optional Redis integration** for session management (can be disabled).

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-repo/hmac-file-server.git
   cd hmac-file-server
   ```

2. **Build the server**:
   Make sure you have [Go](https://golang.org/) installed.
   ```bash
   go build -o hmac-file-server hmac-file-server.go
   ```

3. **Create the configuration file**:
   The server requires a `config.toml` file for its configuration. See the example below.

## Configuration

Create a `config.toml` file in the same directory as the server or specify a custom path using the `--config` flag. Here is an example configuration:

```toml
# IP address and port to listen on (e.g. "[::1]:8080" for localhost IPv6)
ListenPort = "[::1]:8080"

# Secret used for HMAC (must match the one in prosody.conf.lua)
Secret = "orbit7-shadow23-breeze91-echo17"

# Directory where files will be stored
StoreDir = "/mnt/storage/hmac-file-server"

# Subdirectory for HTTP upload/download requests
UploadSubDir = "upload/"

# Logging settings
LogLevel = "info"   # Log level (info, warn, error)
LogFile = "/var/log/hmac-file-server.log"   # Path to log file

# Retry settings for uploads
MaxRetries = 5    # Maximum number of retries for failed uploads
RetryDelay = 2    # Delay in seconds between retries

# Redis configuration (optional, leave blank if not used)
RedisAddr = ""   # e.g., "localhost:6379" if using Redis
RedisPassword = ""
RedisDB = 0

# Metrics settings for Prometheus (optional)
MetricsEnabled = true
MetricsPort = ":9090"    # Port for Prometheus metrics, e.g., ":9090"

# Chunk size for uploads (in bytes)
ChunkSize = 1048576  # Default chunk size of 1MB
```

## Usage

Run the server with the following command:

```bash
./hmac-file-server --config ./config.toml
```

### Command-line Flags

- `--config`: Path to the configuration file (default: `./config.toml`).

## HMAC File Upload Process

When uploading files, the URL must contain the HMAC signature as a query parameter. The server checks this signature to ensure that the upload request is valid.

### Example:

If the file is stored at `/upload/testfile.txt`, the client must calculate the HMAC using the file path and size, and include it in the URL like this:

```http
PUT /upload/testfile.txt?v=your_hmac_signature
```

The server will verify the HMAC signature before accepting the upload.

### HMAC Calculation

For HMAC generation, the following inputs are used:

1. **File Path**: The relative path where the file will be uploaded.
2. **Content Length**: The size of the file being uploaded.
3. **Secret**: The shared secret key from the configuration.

The client must concatenate these values (with a space or null byte depending on protocol) and calculate the HMAC using the secret.

## Prometheus Metrics

If metrics are enabled in the configuration (`MetricsEnabled = true`), the server will expose Prometheus metrics at the specified port (`MetricsPort`).

Metrics include:
- **Upload duration** (`hmac_file_server_upload_duration_seconds`): Time taken for file uploads.
- **Total uploads** (`hmac_file_server_uploads_total`): The number of successful uploads.
- **Upload errors** (`hmac_file_server_upload_errors_total`): The number of failed uploads.

Access the metrics at:

```http
http://localhost:9090/metrics
```

## Logging

- Logs are written to the specified log file (`LogFile` in the config) or `stdout` if no file is specified.
- The logging level can be set via the `LogLevel` configuration option (`info`, `warn`, `error`).

## Redis Integration (Optional)

Redis can be used for session management if enabled in the configuration. To disable Redis, leave the `RedisAddr`, `RedisPassword`, and `RedisDB` fields blank in the config.

## Example Systemd Service

Here is an example of how you can set up the HMAC file server as a systemd service:

```ini
[Unit]
Description=HMAC File Server
After=network.target

[Service]
ExecStart=/path/to/hmac-file-server --config /path/to/config.toml
Restart=on-failure
User=hmac-file-server
Group=hmac-file-server
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
```

## Version 1.0.6 (Final)

This version marks the final release of version 1.0.6 of the HMAC File Server.

## License

This project is licensed under the MIT License.

Mit ❤️ codiert – während um uns die Welt im Chaos versinkt!
