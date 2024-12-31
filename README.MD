# HMAC File Server
A secure file server with HMAC authentication and configurable features.

**HMAC File Server** is a secure, scalable, and feature-rich file server with advanced capabilities like HMAC authentication, resumable uploads, chunked uploads, file versioning, deduplication, optional ClamAV scanning for file integrity and security, and image thumbnail generation. This server is built with extensibility and operational monitoring in mind, including Prometheus metrics support and Redis integration.

> **Credits:** The **HMAC File Server** is based on the source code of [Thomas Leister's prosody-filer](https://github.com/ThomasLeister/prosody-filer). Many features and design elements have been inspired or derived from this project.

---

## Features

- **HMAC Authentication:** Secure file uploads and downloads with HMAC tokens.
- **File Versioning:** Enable versioning for uploaded files with configurable retention.
- **Chunked and Resumable Uploads:** Handle large files efficiently with support for resumable and chunked uploads.
- **Deduplication:** Automatically remove duplicate files based on hashing for storage efficiency.
- **ClamAV Scanning:** Optional virus scanning for uploaded files.
- **Prometheus Metrics:** Monitor system and application-level metrics.
- **Redis Integration:** Use Redis for caching or storing application states.
- **File Expiration:** Automatically delete files after a specified TTL.
- **Graceful Shutdown:** Handles signals and ensures proper cleanup.
- **Auto-Adjust Worker Scaling:** Dynamically optimize worker threads based on system resources.
- **Precaching:** Pre-cache file structures on startup for faster access.
- **Thumbnail Creation:** Generate image thumbnails for uploaded files.
- **ISO Container Management:** Optional mounting and handling of ISO-based filesystems.

---

## Repository

- **Primary Repository**: [GitHub Repository](https://github.com/PlusOne/hmac-file-server)
- **Alternative Repository**: [uuxo.net Git Repository](https://git.uuxo.net/uuxo/hmac-file-server)

---

## Installation

### Prerequisites

- **Go 1.20+**
- **Redis** (optional, if Redis integration is enabled)
- **ClamAV** (optional, if file scanning is enabled)
- **genisoimage** (optional, if ISO container management is enabled)

### Clone and Build

```bash
# Clone from the primary repository
git clone https://github.com/PlusOne/hmac-file-server.git

# OR clone from the alternative repository
git clone https://git.uuxo.net/uuxo/hmac-file-server.git

cd hmac-file-server
go build -o hmac-file-server main.go
```

#### Build for `arm64`
```bash
cd /path/to/hmac-file-server
GOOS=linux GOARCH=arm64 go build -o ~/Temp/hmac-file-server-2.3-stable_arm64 main.go
```
#### Build for `amd64`
```bash
cd /path/to/hmac-file-server
GOOS=linux GOARCH=amd64 go build -o ~/Temp/hmac-file-server-2.3-stable_amd64 main.go
```

---

## Configuration

The server configuration is managed through a `config.toml` file. Below are the supported configuration options:

### Auto-Adjust Feature

When `AutoAdjustWorkers` is enabled, the number of workers for HMAC operations and ClamAV scans is dynamically determined based on system resources. This ensures efficient resource utilization.

If `AutoAdjustWorkers = true`, the values for `NumWorkers` and `NumScanWorkers` in the configuration file will be ignored, and the server will automatically adjust these values.

### Network Events Monitoring

Setting `NetworkEvents = false` in the server configuration disables the logging and tracking of network-related events within the application. This means that functionalities such as monitoring IP changes or recording network activity will be turned off.

### Precaching

The `precaching` feature allows the server to pre-cache storage paths for faster access. This can improve performance by reducing the time needed to access frequently used storage paths.

### Thumbnail Creation

Set `enabled = true` in the `[thumbnails]` section of `config.toml` to enable image thumbnail generation.

---

## Example `config.toml`

Below is an example configuration file (`config.toml`) you can use as a reference (with sensitive data replaced by placeholder/example data):

```toml
# Server configuration
listenport = "8080"  # TCP port for incoming requests
unixsocket = false   # Use Unix domain socket instead of TCP
storagepath = "/path/to/hmac-file-server/data/"  # Directory to store uploaded files
loglevel = "debug"   # Logging level: "debug", "info", "warn", "error"
logfile = "/path/to/hmac-file-server.log"  # Path to log file; leave empty to use stdout
metricsenabled = true   # Enable Prometheus metrics
metricsport = "9090"    # Port for Prometheus metrics
deduplicationenabled = true
minfreebytes = "5GB"     # Minimum free disk space required
filettl = "2Y"           # Time-to-live for files (2 years)
filettlenabled = false   # Enable TTL checks and cleanup
autoadjustworkers = true # Automatically adjust worker threads based on load
networkevents = false    # Enable detailed network event logging
pidfilepath = "./hmac-file-server.pid" # Path to PID file
precaching = true        # Pre-cache file structures on startup
tempPath = "/tmp/hmac-file-server"  # Path for temporary file uploads

# Deduplication settings
[deduplication]
enabled = true
directory = "/path/to/hmac-file-server/deduplication/"  # Path to deduplication metadata store

# Thumbnails settings
[thumbnails]
enabled = true
directory = "/path/to/hmac-file-server/thumbnails/"  # Directory for storing thumbnails
size = "200x200"  # Thumbnail dimensions
thumbnailintervalscan = "1h"  # Interval for scheduled thumbnail generation
concurrency = 5  # Number of concurrent thumbnail generation tasks

# ISO settings
[iso]
enabled = false
size = "1TB"  # Maximum ISO size
mountpoint = "/path/to/hmac-file-server/iso/"  # ISO mount point
charset = "utf-8"  # Filesystem character set encoding

# Timeout settings
[timeouts]
readtimeout = "3600s"    # Maximum time to read a request (1 hour)
writetimeout = "3600s"   # Maximum time to write a response (1 hour)
idletimeout = "3600s"    # Maximum keep-alive time for idle connections (1 hour)

# Security settings
[security]
secret = "your-secure-secret-key"  # HMAC shared secret key (change to a secure value)

# Versioning settings
[versioning]
enableversioning = false
maxversions = 1  # Number of file versions to retain

# Upload settings
[uploads]
resumableuploadsenabled = false
chunkeduploadsenabled = true
chunksize = "32MB"  # Chunk size for uploads
allowedextensions = ["*"]  # All file types are allowed for uploads

# Downloads settings
[downloads]
resumabledownloadsenabled = false
chunkeddownloadsenabled = true
chunksize = "32MB"

# ClamAV settings
[clamav]
clamavenabled = true
clamavsocket = "/path/to/clamav/clamd.ctl"  # Path to ClamAV socket
numscanworkers = 4  # Number of concurrent scan workers
scanfileextensions = [
    ".exe", ".dll", ".bin", ".com", ".bat",
    ".sh", ".php", ".js"
]

# Redis settings
[redis]
redisenabled = true
redisdbindex = 0
redisaddr = "localhost:6379"  # Redis server address
redispassword = ""            # Redis password if required
redishealthcheckinterval = "120s"  # Interval for Redis health checks

# Worker settings
[workers]
numworkers = 4
uploadqueuesize = 5000

# File settings
[file]
filerevision = 1  # Internal revision number for file handling logic

# Logging settings
[logging]
level = "info"
file = "/var/log/hmac-file-server.log"
max_size = 100
max_backups = 7
max_age = 30
compress = true
```

---

## Configuration Verification

The application ensures that all configuration parameters defined in `config.toml` are correctly implemented and operational. During startup, the server performs the following verification steps:

1. **Configuration Parsing:**
   - Parses the `config.toml` file into the application's `Config` struct.
   
2. **Validation:**
   - Checks that all required configuration parameters are set.
   - Validates the correctness of configuration values (e.g., proper duration formats, non-empty directories).
   
3. **Service Initialization:**
   - Initializes services like Redis and ClamAV based on the configuration.
   - Ensures that conditional services (e.g., Thumbnails, ISO) are only started if enabled in the configuration.

If any configuration parameter is missing or invalid, the server will log an error and terminate to prevent running with incorrect settings.

---

## Running the Server

### Basic Usage

Run the server with a configuration file:

```bash
./hmac-file-server -config ./config.toml
```

Ensure that the `config.toml` is correctly set up before running the server.

---

### Metrics Server

If `metricsenabled` is set to `true`, the Prometheus metrics server will be available on the port specified in `metricsport` (e.g., `http://localhost:9090/metrics`).

Additional metrics for deduplication and ISO container operations are now available.

---

## Health Checks

The server includes built-in health checks to verify that all configured services are operational. Logs will provide detailed information about the status of each service and any issues encountered during startup.

---

## Testing

To run the server locally for development:

```bash
go run main.go -config ./config.toml
```

Use tools like **cURL** or **Postman** to test file uploads and downloads.

### Example File Upload with HMAC Token

```bash
curl -X PUT -H "Authorization: Bearer <HMAC-TOKEN>" -F "file=@example.txt" http://localhost:8080/uploads/example.txt
```

Replace `<HMAC-TOKEN>` with a valid HMAC signature generated using the configured `secret`.

---

## Monitoring

Prometheus metrics include:

- **File Operations:**
  - File upload/download durations
  - Uploaded/downloaded file sizes
  - Total number of uploads/downloads
  - Total number of upload/download errors

- **System Metrics:**
  - Memory usage
  - CPU usage
  - Number of goroutines
  - Active connections

- **HTTP Requests:**
  - Total HTTP requests broken down by method and path

Access the metrics at `http://localhost:9090/metrics` (assuming default `metricsport`).

---

## Additional Features

- **Deduplication:** Automatically remove duplicate files based on SHA256 hashing to save storage space.
- **Versioning:** Store multiple versions of files and retain a configurable number of versions.
- **ClamAV Integration:** Scan uploaded files for viruses using ClamAV to ensure file integrity and security.
- **Redis Caching:** Utilize Redis for caching file metadata to improve access times and performance.
- **Auto-Adjust Worker Scaling:** Optimize the number of workers dynamically based on system resources to maintain optimal performance.
- **Precaching:** Pre-cache file structures on startup to reduce access times for frequently accessed files.
- **Thumbnail Creation:** Generate image thumbnails for uploaded files to provide quick previews.
- **ISO Container Management:** Optional mounting and handling of ISO-based filesystems for specialized storage needs.

---

### Overview of Other Projects (xep0363)

| Feature/Project             | HMAC FS | mod_http_upload_ext | xmpp-http-upload (horazont) | Prosody Filer | ngx_http_upload | xmpp-http-upload (nyovaya) |
|-----------------------------|---------|----------------------|-----------------------------|---------------|------------------|----------------------------|
| **Language**                | Go      | PHP                  | Python                      | Go            | C (Nginx)         | Python                     |
| **Environment**             | Standalone | Prosody module       | Standalone                 | Standalone    | Nginx            | Standalone                 |
| **XMPP**                    | No      | Yes                  | Yes                         | Yes           | No               | Yes                        |
| **External Storage**        | Yes     | No                   | Possible via plugins        | No            | No               | Yes                        |
| **Authentication / Security** | HMAC    | Token-based          | Token-based                 | None          | Basic / None      | Token-based                |

---

## Build & Run

1. **Clone the Repository:**

    ```bash
    git clone https://github.com/PlusOne/hmac-file-server.git
    cd hmac-file-server
    ```

2. **Build the Server:**

    ```bash
    go build -o hmac-file-server main.go
    ```

3. **Run the Server:**

    ```bash
    ./hmac-file-server -config ./config.toml
    ```

---

## Best Practices and Recommendations

1. **Configuration Consistency:**
   - Ensure all configuration keys in `config.toml` match those expected in the code. For example, in the `[thumbnails]` section, use `thumbnailintervalscan` instead of `scanInterval` to align with the code.

2. **Security:**
   - **HMAC Secret:**  
     - **Change Immediately:** The `secret` under `[security]` should be a strong, unique string. Replace `"your-secure-secret-key"` with a securely generated key.
   - **ClamAV:**  
     - Ensure ClamAV is installed and the `clamavsocket` path is correct if `[clamav].clamavenabled` is `true`.
   - **Redis:**  
     - Secure your Redis instance, especially if it's exposed to external networks. Use strong passwords and restrict access as needed.

3. **Resource Allocation:**
   - Adjust `numworkers` and `uploadqueuesize` in the `[workers]` section based on your server's hardware capabilities and expected traffic.
   - Monitor system performance to ensure that auto-adjust features are working optimally.

4. **Monitoring and Metrics:**
   - Regularly monitor Prometheus metrics to keep an eye on server performance, resource usage, and potential issues.
   - Set up alerts based on critical metrics to proactively handle problems.

5. **Logging:**
   - Ensure that log files are rotated and managed properly to prevent disk space issues.
   - Consider enabling JSON logging (`loggingjson = true`) for better integration with log management systems.

6. **Testing:**
   - Perform thorough testing of file uploads/downloads, especially with large files and under high load.
   - Test ClamAV scanning with both clean and malicious files to ensure security features are functioning correctly.

7. **Maintenance:**
   - Regularly update dependencies to benefit from security patches and performance improvements.
   - Clean up old file versions and ensure deduplication is functioning to optimize storage usage.

8. **Backup:**
   - Implement a backup strategy for critical data, especially if file versioning is enabled.

9. **Documentation:**
   - Keep the `README.md` and other documentation up-to-date with any code changes to assist in maintenance and onboarding new contributors.

---

## Troubleshooting

- **Cannot Connect to Redis:**
  - Ensure Redis is running and accessible at the address specified in `redisaddr`.
  - Verify that the `redispassword` is correct if authentication is enabled.
  
- **ClamAV Scanning Fails:**
  - Check if ClamAV is installed and the `clamavsocket` path is correct.
  - Ensure that the ClamAV daemon (`clamd`) is running.

- **Insufficient Disk Space:**
  - Monitor the disk space and adjust `minfreebytes` in the configuration as needed.
  - Enable file TTL and cleanup to automatically remove old files.

- **Metrics Not Available:**
  - Ensure that `metricsenabled` is set to `true` and the server is running without errors.
  - Check if the specified `metricsport` is not blocked by a firewall.

- **Thumbnail Generation Not Working:**
  - Verify that the `[thumbnails].enabled` is set to `true` and the `directory` exists with appropriate permissions.
  - Check the logs for any errors related to image processing.

---

## Contributing

Contributions are welcome! Please follow these steps to contribute:

1. **Fork the Repository**
2. **Create a Feature Branch**

    ```bash
    git checkout -b feature/YourFeatureName
    ```

3. **Commit Your Changes**

    ```bash
    git commit -m "Add your message here"
    ```

4. **Push to the Branch**

    ```bash
    git push origin feature/YourFeatureName
    ```

5. **Open a Pull Request**

Provide a clear description of your changes and the problem they address.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

By following this updated `README.md`, you can ensure that users and contributors have a clear understanding of the **HMAC File Server**'s capabilities, configuration options, and best practices for deployment and maintenance.