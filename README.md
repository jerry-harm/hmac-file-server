
# HMAC File Server Documentation

## Key Features
1. **Session Token Management**: Each client uses a session token (`X-Session-Token`) to track its progress during file uploads. If no token is provided by the client, the server generates one and sends it back in the response header.
2. **Resumable Upload Support**: If an upload is interrupted, the progress is stored in Redis using the session token. When the client reconnects with the same session token, the upload is resumed from where it left off.
3. **CORS Handling for Cross-Origin Requests**: The server adds CORS headers to handle cross-origin requests. This includes the ability for clients like Conversations or Dino to send custom headers (like the session token).
4. **Redis Integration for Upload Progress**: The upload progress is stored in Redis, which allows for resumable uploads across network interruptions.
5. **File Upload and Resumption**: The core functionality is reading file chunks from the client, saving them to disk, and resuming uploads if the session is interrupted.
6. **Logging Configuration**: The server logs to a file (if specified in `config.toml`) or to standard output. The log level can also be configured.
7. **Metrics via Prometheus**: The server exposes Prometheus metrics related to file uploads and server performance.
8. **File Retention and Cleanup Policies**: The server has a retention policy that controls how long files are kept or based on size limits.

## Configuration (`config.toml`)
The configuration file defines various settings that control the server's behavior:

```toml
ListenPort = ":8080"  # Port to listen on
UnixSocket = false  # Whether to use Unix socket instead of TCP
Secret = "mysecret"  # Secret for HMAC generation
StoreDir = "/data/uploads"  # Directory to store uploaded files
UploadSubDir = "uploads"  # Subdirectory for uploads
LogLevel = "info"  # Logging level
LogFile = "/var/log/hmac-file-server.log"  # Path to the log file
MaxRetries = 5  # Maximum number of upload retries
RetryDelay = 2  # Delay between retries
EnableGetRetries = true  # Allow retries for GET requests
BlockAfterFails = 3  # Block IP after this many failed attempts
BlockDuration = 300  # Block duration in seconds
AutoUnban = true  # Automatically unban IP after a certain time
AutoBanTime = 600  # Time before an IP is automatically unbanned
DeleteFiles = true  # Enable file deletion after a certain period
DeleteFilesAfterPeriod = "30d"  # Delete files older than 30 days
NumCores = "auto"  # Use all available CPU cores
ReaskSecretEnabled = true  # Re-ask for HMAC secret periodically
ReaskSecretInterval = "24h"  # Interval to re-ask for HMAC secret
MetricsEnabled = true  # Enable Prometheus metrics
MetricsPort = ":9090"  # Port for Prometheus metrics
ChecksumVerification = true  # Enable checksum verification for uploads
RetentionPolicyEnabled = true  # Enable file retention policies
MaxRetentionSize = 10737418240  # Maximum retention size in bytes (10 GB)
MaxRetentionTime = "30d"  # Maximum retention time in days
RedisAddr = "localhost:6379"  # Redis server address
RedisPassword = ""  # Redis server password
RedisDB = 0  # Redis database number
ReadTimeout = 900  # Read timeout in seconds
WriteTimeout = 900  # Write timeout in seconds
BufferSize = 65536  # Buffer size for file uploads in bytes
```

## Metrics Exposed

```toml
hmac_file_server_goroutines: The current number of goroutines running in the HMAC file server.
hmac_file_server_upload_duration_seconds: A histogram measuring the duration of file uploads in seconds for the HMAC file server.
hmac_file_server_upload_errors_total: The total count of errors encountered during file uploads in the HMAC file server.
hmac_file_server_uploads_total: The total number of successfully completed file uploads in the HMAC file server.
```

## HMAC File Server v1.0.5 - Release Notes

## **Core Features:**
1. **HMAC-Based Upload Authentication:**
   - Uses HMAC signatures to authenticate and verify uploads.
   - Configurable `Secret` for HMAC validation via a pool for efficient reuse.

2. **File Upload & Download Support:**
   - Supports PUT (file upload) and GET (file retrieval).
   - CORS headers for cross-origin file uploads compatible with XMPP clients.
   - Support for large files with configurable buffer size.
   - Chunked file upload processing.

3. **Cross-Origin Resource Sharing (CORS):**
   - Full CORS support for `OPTIONS`, `GET`, and `PUT` requests.
   - `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Methods`, and proper preflight handling for XEP-0363 compliance.

4. **Prometheus Metrics:**
   - Integrated metrics for monitoring:
     - `file_server_goroutines`: Active goroutines.
     - `file_server_upload_duration_seconds`: Upload duration histogram.
     - `file_server_upload_errors_total`: Total upload errors.
     - `file_server_uploads_total`: Total successful uploads.
   - Available via `/metrics` endpoint for Prometheus scraping.

5. **Checksum Verification:**
   - Supports optional checksum verification for uploads with SHA-256.

6. **Concurrency and Performance:**
   - Automatic or manually configured CPU core allocation (`NumCores`).
   - Redis client initialization for potential distributed systems.
   - In-memory caching with eviction policies using go-cache.

7. **Retention and File Cleanup Policies:**
   - Automatic file deletion after a specified retention period (`DeleteFilesAfterPeriod`).
   - Configurable maximum retention size (`MaxRetentionSize`) and time (`MaxRetentionTime`).

8. **Logging & Reports:**
   - Detailed logging for errors and operations.
   - File deletion reports are written to a specified file path.
   - Log levels configurable (`info`, `warn`, `debug`).

## **System Integration:**

### **Systemd Service Example:**

```ini
[Unit]
Description=HMAC File Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hmac-file-server -config /etc/hmac-file-server/config.toml
Restart=always
User=hmac-file-server
Group=hmac
WorkingDirectory=/var/hmac-file-server
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

## **NGINX Reverse Proxy Example:**

```nginx
server {
    listen 80;
    server_name fileserver.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    client_max_body_size 1G;  # Adjust as per requirements
}
```

## **Generated URL for Download:**
For each file uploaded to the HMAC File Server, a generated URL follows the pattern:
```
https://fileserver.example.com/upload/{generated-file-path}
```
Where `{generated-file-path}` will be the path stored in your configured `StoreDir`. Each file will have a unique hash path.

---

## **Conclusion:**
This final release integrates XEP-0363 file upload support for XMPP clients such as **Conversations**, **Dino**, **Gajim**, and more, ensuring compatibility with existing chat infrastructures such as ejabberd and Prosody. The server efficiently handles large file uploads, retains security via HMAC-based authentication, and offers a fully monitorable solution with Prometheus metrics.

These configurations allow seamless integration with a reverse proxy setup and systemd services for production environments.

---
