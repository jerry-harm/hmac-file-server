
# HMAC File Server v1.0.5 - Release Notes

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

---

## **System Integration:**

### **1. Systemd Service Example:**
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

### **2. NGINX Reverse Proxy Example:**
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

### **3. ejabberd File Upload Configuration:**
```yaml
mod_http_upload:
  secret: "your-hmac-secret"
  docroot: "/var/hmac-file-server/upload"
  put_url: "https://fileserver.example.com/upload/{file}"

mod_http_upload_external:
  base_url: "https://fileserver.example.com/upload"
  secret: "your-hmac-secret"
  docroot: "/var/hmac-file-server/upload"
```

### **4. Prosody File Upload Configuration (mod_http_upload_external):**
```lua
modules_enabled = {
  "http_upload_external";
}

http_upload_external_base_url = "https://fileserver.example.com/upload/"
http_upload_external_secret = "your-hmac-secret"
http_upload_external_file_size_limit = 104857600 -- 100 MB limit
```

---

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

| Setting                             | Description                                                                                | Mapped to Functionality                                                                |
|:------------------------------------|:-------------------------------------------------------------------------------------------|:---------------------------------------------------------------------------------------|
| ListenPort                          | The port the server listens on.                                                            | Used in net.Listen(proto, address) in the main function.                               |
| UnixSocket, UnixSocketPath          | If true, the server will use a Unix socket.                                                | Used to determine whether the server listens on a Unix socket or TCP in net.Listen.    |
| Secret                              | The secret key used for HMAC generation (security feature).                                | Used to initialize the HMAC pool.                                                      |
| StoreDir, UploadSubDir              | Where uploaded files are stored.                                                           | Used to save uploaded files to the correct directory.                                  |
| LogLevel, LogFile                   | Controls the logging level and output destination.                                         | Configures log output and verbosity.                                                   |
| MaxRetries, RetryDelay              | Controls the retry behavior when handling uploads.                                         | Would be used in retry logic (if implemented for retries on failure).                  |
| AutoUnban, AutoBanTime              | Controls IP blocking/unblocking if the server uses a banning mechanism.                    | No direct use of banning/unbanning is shown in the provided code.                      |
| DeleteFilesAfterPeriod, DeleteFiles | If true, old files are deleted after the specified period.                                 | Settings for retention policies (the logic isn't fully implemented in the code).       |
| NumCores                            | Determines how many CPU cores the server uses.                                             | Passed to runtime.GOMAXPROCS() to control parallelism.                                 |
| MetricsEnabled, MetricsPort         | Enables Prometheus metrics and sets the port for the metrics server.                       | Used to expose /metrics endpoint with Prometheus metrics.                              |
| ChecksumVerification                | Ensures files have checksums (not implemented in the code).                                | This setting is present but the functionality is not implemented in the provided code. |
| MaxRetentionSize, MaxRetentionTime  | Sets file retention policies, either based on file size or the age of the files.           | This setting is present but the actual cleanup logic is not implemented in the code.   |
| RedisAddr, RedisPassword, RedisDB   | Connection details for Redis, which tracks upload progress and supports resumable uploads. | Used in InitRedisClient() to initialize the Redis client.                              |


# HMAC File Server Systemd Service Example

## systemd Service File Example

```ini
[Unit]
Description=HMAC File Server
After=network.target

[Service]
Type=simple
User=your_user  # Replace with the user you want to run the server as
Group=your_group  # Replace with the group you want to run the server as
WorkingDirectory=/path/to/your/hmac-file-server  # Replace with the directory where the binary or script resides
ExecStart=/path/to/your/hmac-file-server/hmac-file-server -config /path/to/your/config.toml
Restart=on-failure

# Optional: set up resource limits
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
```

## Steps to Install and Enable the Service

1. **Create the systemd service file**:
   ```bash
   sudo nano /etc/systemd/system/hmac-file-server.service
   ```

2. **Copy and paste the above content** and update:
   - `User`: the user that will run the service.
   - `Group`: the group that will run the service.
   - `WorkingDirectory`: the directory where the HMAC File Server binary/script is located.
   - `ExecStart`: the command to start the file server (update the paths to your binary and `config.toml`).

3. **Save and exit** the file.

4. **Reload systemd to recognize the new service**:
   ```bash
   sudo systemctl daemon-reload
   ```

5. **Start the service**:
   ```bash
   sudo systemctl start hmac-file-server
   ```

6. **Enable the service to start on boot**:
   ```bash
   sudo systemctl enable hmac-file-server
   ```

7. **Check the status** of the service to ensure it's running:
   ```bash
   sudo systemctl status hmac-file-server
   ```

This will ensure that the HMAC File Server starts automatically and runs as a system service.


[Install]
WantedBy=multi-user.target


### **Download:**
[Download HMAC File Server v1.0.5 amd64](https://github.com/PlusOne/hmac-file-server/releases/download/1.0.5/hmac-file-server-v1.0.5-linux-amd64) 
[Download HMAC File Server v1.0.5 arm64](https://github.com/PlusOne/hmac-file-server/releases/download/1.0.5/hmac-file-server-v1.0.5-linux-arm64) 
