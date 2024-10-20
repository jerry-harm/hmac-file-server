
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

### **Download:**
[Download HMAC File Server v1.0.5](https://fileserver.example.com/download/hmac-file-server-v1.0.5.tar.gz)
