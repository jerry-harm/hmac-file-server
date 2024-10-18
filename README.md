
# HMAC File Server

This project provides a secure file upload server that uses HMAC-based authentication to validate uploads. It integrates with XMPP servers like ejabberd or Prosody to handle HTTP file uploads using the `mod_http_upload_external` module. The server supports chunked uploads, Prometheus metrics for monitoring, and detailed logging to a file.

## Features

### 1. HMAC Validation for Secure Uploads
- **HMAC-Based Authentication**: The server validates file uploads by verifying an HMAC signature sent as a query parameter in the upload URL. The HMAC is calculated using a shared secret and includes the file path, content length, and MIME type (for protocol version `v2` or `token`).
- **Compatibility with ejabberd/Prosody**: The server supports the HMAC generation methods required by **ejabberd** and **Prosody** when using `mod_http_upload_external`.
- **Logging of HMAC Details**: Logs include detailed HMAC validation information, such as expected and received HMACs, file paths, content lengths, and MIME types.

### 2. Chunked File Uploads
- **Chunked Transfer Encoding**: The server supports chunked uploads by reading incoming files in chunks, allowing large file uploads without requiring the entire file to be stored in memory.
- **Efficient File Handling**: Files are written directly to disk in small chunks, ensuring the server can handle large files while conserving memory.

### 3. Prometheus Metrics Integration
- **Real-Time Monitoring**: The server exposes key metrics via the `/metrics` endpoint (default port `9090`) for Prometheus monitoring. These metrics include:
  - **Number of goroutines**: Shows the number of active goroutines in the server.
  - **Total uploads**: Tracks the total number of file uploads, with success/failure labels.
  - **Total downloads**: Tracks the total number of file downloads, with success/failure labels.
  - **Upload duration**: A histogram of upload durations, useful for monitoring performance.
- **Easy Integration with Prometheus**: The server is ready to be integrated into a Prometheus-based monitoring stack to track health and performance.

### 4. File Logging
- **Log to File**: The server writes logs to a file specified in the configuration (`LogFile`), providing detailed information about HMAC validation, file uploads, and server activity.

### 5. Configuration via TOML
- **TOML Configuration**: The server is configurable via a TOML file, allowing you to set key parameters such as:
  - **Server ports** (`ListenPort`, `MetricsPort`): Control the ports for the file upload server and the Prometheus metrics endpoint.
  - **HMAC Secret** (`Secret`): Set the shared secret used for HMAC validation.
  - **Storage Directories** (`StoreDir`, `UploadSubDir`): Specify where uploaded files are stored.
  - **Log File** (`LogFile`): Configure the log file location.

### 6. Dynamic Protocol Handling
- **Supports Multiple HMAC Protocols**: The server supports both the legacy `v` protocol (file path + content length) and the newer `v2` or `token` protocols (file path + content length + MIME type), ensuring compatibility with older and newer XMPP configurations.

## Example Configuration (`config.toml`):

```toml
ListenPort = ":8080"               # Port for file uploads
MetricsPort = ":9090"              # Port for Prometheus metrics
Secret = "your-shared-secret"      # Shared HMAC secret for validation
StoreDir = "/mnt/storage/uploads"  # Directory where files will be stored
UploadSubDir = "upload"            # Subdirectory for uploads
LogFile = "/var/log/hmac-file-server.log" # Path for log file
```

## Usage

1. **Upload a File**: Clients (like ejabberd/Prosody) can upload files to the server by calculating an HMAC signature and including it in the query string.
2. **Monitor with Prometheus**: You can scrape the `/metrics` endpoint with Prometheus to monitor the performance and health of the server in real time.
3. **Check Logs**: Review logs in the specified log file to troubleshoot any upload issues or inspect server activity.

## License

This project is licensed under the MIT License.
