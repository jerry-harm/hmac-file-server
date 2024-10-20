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

=======
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


# NGINX and Apache2 as Reverse Proxy for HMAC File Server

## NGINX Configuration

To set up NGINX as a reverse proxy for HMAC File Server, follow the steps below:

1. **Install NGINX** (if not installed):
   ```bash
   sudo apt update
   sudo apt install nginx
   ```

2. **Edit the NGINX configuration**:
   You can either edit the default server block or create a new configuration file in `/etc/nginx/sites-available/`.

   Example configuration for reverse proxy:

   ```nginx
   server {
       listen 80;
       server_name hmac-file-server.example.com;

       location / {
           proxy_pass http://127.0.0.1:8080;  # Replace with the actual HMAC File Server address
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;

           # WebSocket support (optional)
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection "upgrade";
       }
   }
   ```

3. **Enable the configuration**:
   ```bash
   sudo ln -s /etc/nginx/sites-available/hmac-file-server /etc/nginx/sites-enabled/
   ```

4. **Test the configuration**:
   ```bash
   sudo nginx -t
   ```

5. **Restart NGINX**:
   ```bash
   sudo systemctl restart nginx
   ```

## Apache2 Configuration

To set up Apache2 as a reverse proxy for HMAC File Server, follow the steps below:

1. **Install Apache2** (if not installed):
   ```bash
   sudo apt update
   sudo apt install apache2
   ```

2. **Enable required Apache modules**:
   ```bash
   sudo a2enmod proxy
   sudo a2enmod proxy_http
   ```

3. **Edit the Apache configuration**:
   Add the following configuration to the Apache configuration file (`/etc/apache2/sites-available/000-default.conf` or a new file in `/etc/apache2/sites-available/`).

   Example configuration for reverse proxy:

   ```apache
   <VirtualHost *:80>
       ServerName hmac-file-server.example.com

       ProxyPreserveHost On
       ProxyPass / http://127.0.0.1:8080/  # Replace with the actual HMAC File Server address
       ProxyPassReverse / http://127.0.0.1:8080/

       # WebSocket support (optional)
       RewriteEngine On
       RewriteCond %{HTTP:Upgrade} =websocket [NC]
       RewriteRule /(.*) ws://127.0.0.1:8080/$1 [P,L]
   </VirtualHost>
   ```

4. **Enable the site configuration**:
   ```bash
   sudo a2ensite hmac-file-server
   ```

5. **Test the configuration**:
   ```bash
   sudo apache2ctl configtest
   ```

6. **Restart Apache**:
   ```bash
   sudo systemctl restart apache2
   ```

With this setup, both NGINX and Apache2 can act as reverse proxies for the HMAC File Server, handling incoming requests and forwarding them to the HMAC File Server backend.


## Comparison of Leister's Prosody Filer and HMAC File Server: Features, Performance, and Scalability

"Contributions to Thomas Leister's work on Prosody Filer are highly appreciated—many thanks for laying the foundation for secure and efficient file uploads!"

| Aspect                | Leister Script (Prosody Filer)                                                         | HMAC File Server                                                                                 |
|:----------------------|:---------------------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------|
| Configuration         | Uses a config.toml file for basic settings like listen port, secret, store directory.  | Uses a config.toml file with more settings (retry, cores, retention, Redis).                     |
| HMAC Handling         | Implements HMAC for verifying uploads using different protocols (v, v2, token).        | HMAC is used for secure file uploads and file path verification.                                 |
| Upload Handling       | Simple file upload handling with HMAC verification but no resumable upload support.    | Supports resumable file uploads with state stored in Redis.                                      |
| Resumable Uploads     | No support for resumable uploads, each upload must be completed in a single session.   | Fully supports resumable uploads using session tokens and Redis for tracking progress.           |
| File Storage          | Stores uploaded files in a specified directory with basic path handling.               | Stores files in a specified directory with additional retention policies for cleanup.            |
| Error Handling        | Basic error handling, returns HTTP error codes for invalid HMAC, internal errors, etc. | Detailed error handling, including support for resumable uploads, timeouts, and retries.         |
| Logging               | Uses logrus for logging, includes options for log levels (info, warn, error).          | Uses logrus for logging but with more customizable options for log files and levels.             |
| Redis Integration     | No Redis integration, doesn't store upload state for resumable uploads.                | Integrated with Redis for tracking upload progress and resumable uploads.                        |
| Checksum Verification | Supports basic HMAC verification but no checksum verification of file content.         | Includes checksum verification and validation (based on configuration).                          |
| Metrics               | No metrics support.                                                                    | Prometheus metrics exposed for upload duration, errors, and total uploads.                       |
| CORS Handling         | Basic CORS handling for allowed methods and headers.                                   | CORS handling with additional custom headers (like session tokens).                              |
| Compatibility         | Compatible with ejabberd, Prosody, and Metronome using the external upload protocol.   | Designed for more general use cases with multiple clients, but also compatible with XMPP upload. |

### **Download:**

[Download HMAC File Server v1.0.5 amd64](https://github.com/PlusOne/hmac-file-server/releases/download/1.0.5/hmac-file-server-v1.0.5-linux-amd64) 

[Download HMAC File Server v1.0.5 arm64](https://github.com/PlusOne/hmac-file-server/releases/download/1.0.5/hmac-file-server-v1.0.5-linux-arm64) 

>>>>>>> ef2744c1222dd1cf71cd8db230bc3eedba220eee
