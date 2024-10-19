
# HMAC File Server

The **HMAC File Server** is a secure file server that uses HMAC (Hash-based Message Authentication Code) to validate and authorize file uploads and downloads. It is optimized for handling large files, metadata caching with Redis, concurrency tuning, and offers Prometheus metrics.

## Features:

- **HMAC-based authentication** for secure file uploads and downloads.
- **Redis Integration** for metadata caching, improving performance.
- **Concurrency Tuning** with automatic or manual CPU core allocation.
- **Asynchronous File Handling** for faster uploads and parallel processing.
- **Optional Checksum Validation** using SHA-256.
- **Prometheus Metrics** for monitoring file uploads, download times, and errors.
- **Graceful Shutdown** ensures file operations complete before server shutdown.
- **CORS Support** for cross-origin requests.

---

## Latest Release: Version 1.0.5 (October 19, 2024)

### New Features:
- **Redis Integration** for metadata caching.
- **Concurrency Tuning**: Automatic or manual CPU core configuration.
- **Asynchronous File Handling**: Non-blocking file uploads.
- **Checksum Validation**: Optional SHA-256 checksum verification for file integrity.
- **Prometheus Metrics**: Monitoring support for file uploads, errors, and upload durations.
- **Graceful Shutdown**: Safe termination of file operations.
- **CORS Support**: Cross-origin resource sharing for web requests.

### Example `config.toml` Configuration:

```toml
ListenPort = ":8080"
Secret = "stellar-wisdom-orbit-echo"
StoreDir = "/mnt/storage/hmac-file-server/"
UploadSubDir = "upload"
LogLevel = "info"
LogFile = "/var/log/hmac-file-server.log"
MaxRetries = 5
RetryDelay = 2
ChecksumVerification = true
RetentionPolicyEnabled = true
MaxRetentionSize = 10737418240 # 10 GB
MaxRetentionTime = "30d"       # 30 days

# Redis configuration
RedisAddr = "localhost:6379"
RedisPassword = ""
RedisDB = 0

# Metrics configuration
MetricsEnabled = true
MetricsPort = ":9090"

# Concurrency tuning
NumCores = "auto"
```

### NGINX Reverse Proxy Example:

```nginx
server {
    listen 443 ssl;
    server_name hmac.yourdomain.com;

    ssl_certificate /etc/nginx/ssl/hmac.crt;
    ssl_certificate_key /etc/nginx/ssl/hmac.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Previous Releases:

### Version 1.0.4 (October 16, 2024)

- **Prometheus Metrics Integration**: File server metrics exposed via `/metrics`.
- **Improved Error Logging**: Enhanced error messages for file uploads and downloads.
- **Bug Fixes**: Fixed concurrency issues during file upload under high load.

### Version 1.0.3 (October 14, 2024)

- **HMAC-based Authentication**: Secure file uploads and downloads using HMAC tokens.
- **Configurable Upload Subdirectory**: Customizable directory for file storage.
- **Graceful Shutdown Support**: Safe termination of ongoing file operations.
- **Retention Policy**: Automatic deletion of old or excess files based on size and age.

---

## How to Use

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-repo/hmac-file-server.git
   cd hmac-file-server
   ```

2. **Modify the `config.toml` file** with your server configurations.

3. **Run the server**:
   ```bash
   go run hmac-file-server.go -config config.toml
   ```

4. **Monitor Metrics** (optional):
   - Access the Prometheus metrics endpoint at `http://localhost:9090/metrics` (if enabled).

## License

Licensed under the MIT License.

