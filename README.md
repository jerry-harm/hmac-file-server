# HMAC File Server

## Overview

HMAC File Server is a secure file handling server designed for use with XMPP servers like Prosody and ejabberd. It enables HMAC-based file uploads and downloads, rate limiting, auto-banning, auto-file deletion, multicore processing, and caching.

### Key Features
- **HMAC Authentication**: Secure file transfers using HMAC signatures.
- **Retry Mechanism**: Automatic retries for file access and downloads.
- **Disk Space Checks**: Prevents uploads if disk space is low.
- **Rate Limiting & Auto-Banning**: Protects against abuse by limiting failed access attempts.
- **Auto-File Deletion**: Automatically delete files older than a configurable period.
- **Max Upload Size**: Set maximum upload size (default is 1GB) for better control over file handling.
- **Multicore Support**: Efficiently uses all available CPU cores for optimized performance.
- **Caching**: In-memory caching to speed up file metadata handling.
- **Monitoring with Prometheus**: Metrics exposed for monitoring file server performance.
- **HTTP/2 & CORS Support**: For faster and cross-origin file transfers.
- **Systemd Support**: Easily manage as a service.

---

## Configuration and Setup

The server is configured using a `config.toml` file. Below is a sample configuration:

```toml
# Server Configuration
ListenPort = ":8080"                         # The port on which HMAC File Server will listen for HTTP requests
UnixSocket = false                           # Use Unix socket instead of TCP (set to true if you want to use Unix socket)

# Authentication
Secret = "your-secret-key"                   # HMAC secret key for secure file uploads and downloads

# File Storage
StoreDir = "/var/lib/hmac-file-server"       # Directory where uploaded files will be stored
UploadSubDir = "uploads"                     # Sub-directory for file uploads

# Logging
LogLevel = "info"                            # Log level (options: "debug", "info", "warn", "error")

# CPU Configuration
NumCores = "auto"                            # Number of CPU cores to use ("auto" for all available or specify a number)

# Max Upload Size
MaxUploadSize = 1073741824                   # Maximum upload size in bytes (1 GB)

# Retry Logic for File Access
MaxRetries = 5                               # Maximum number of retries if a file is not found
RetryDelay = 2                               # Delay in seconds between retry attempts
EnableGetRetries = true                       # Enable retries for GET requests if files are not found

# Rate Limiting and Auto-Banning
BlockAfterFails = 5                          # Number of failed attempts before blocking a path
BlockDuration = 300                          # Duration (in seconds) to block a path after too many failed attempts
AutoUnban = true                             # Automatically unban a path after a certain period
AutoBanTime = 600                            # Time (in seconds) for how long a path remains banned before auto-unban

# Buffer Configuration
BufferEnabled = true                          # Enable or disable buffer usage for read and write operations
BufferSize = 8192                            # Size of the buffer (in bytes)

# File Deletion Configuration
DeleteFiles = true                           # Enable automatic deletion of files
DeleteFilesAfterPeriod = "30d"              # Period after which files will be deleted (e.g., "30d" for 30 days)

# Report Configuration
WriteReport = true                           # Enable writing a report of deleted files
ReportPath = "/var/log/hmac-file-server/deleted-files-report.log"  # Path for the deletion report log

# Monitoring Configuration
MetricsEnabled = true                         # Enable Prometheus metrics
MetricsPort = ":9090"                        # Port for metrics endpoint
```

### Custom Headers for CORS

In case you are using web-based clients, you may need to handle cross-origin requests (CORS). For that, you can define custom headers as shown below in both Prosody and ejabberd configurations.

---

## Prosody HTTP Upload Integration

You can integrate the HMAC File Server with **Prosody** for HTTP file uploads. Below is a sample configuration for `mod_http_upload`:

```lua
Component "upload.example.com" "http_upload"
    http_upload_path = "/upload/"
    http_external_url = "https://share.example.com"
    max_size = 1073741824 -- 1GB max upload size
    docroot = "/mnt/storage/prosody_uploads"
    external_secret = "replace_with_hmac_file_server_secret"
    custom_headers = {
        ["Access-Control-Allow-Origin"] = "*";
        ["Access-Control-Allow-Methods"] = "GET, HEAD, PUT, OPTIONS";
        ["Access-Control-Allow-Headers"] = "Content-Type";
    }

    -- Optional thumbnail support
    thumbnail = true
```

### Explanation of Configuration:

- **`http_external_url`**: The public URL used for uploaded file access.
- **`max_size`**: Maximum file size for uploads (set to 1GB).
- **`docroot`**: The local directory where uploaded files are stored.
- **`external_secret`**: Use the same HMAC secret as configured in `hmac-file-server`. Replace `"replace_with_hmac_file_server_secret"` with the actual secret.
- **`custom_headers`**: These headers are necessary if you're handling **cross-origin requests** (CORS), especially for web-based clients.

---

## ejabberd HTTP Upload Integration

For **ejabberd**, the HTTP file upload integration with HMAC File Server can be configured as shown below:

```yaml
mod_http_upload:
    max_size: 1073741824  # 1GB max upload size
    thumbnail: true  # Optional thumbnail generation
    put_url: https://share.example.com
    get_url: https://share.example.com
    docroot: /mnt/storage/ejabberd
    external_secret: "replace_with_hmac_file_server_secret"
    custom_headers:
      "Access-Control-Allow-Origin": "*"
      "Access-Control-Allow-Methods": "GET,HEAD,PUT,OPTIONS"
      "Access-Control-Allow-Headers": "Content-Type"
```

### Explanation of Configuration:

- **`put_url`**: The URL used for file uploads.
- **`get_url`**: The URL used for file downloads.
- **`docroot`**: The local directory where the uploaded files are stored.
- **`external_secret`**: Use the same HMAC secret as configured in `hmac-file-server`. Replace `"replace_with_hmac_file_server_secret"` with the actual secret.
- **`custom_headers`**: These headers ensure that the HTTP upload service works with cross-origin requests (CORS).
- **`max_size`**: Maximum size for file uploads (in bytes). The example is set to 1GB.

### Custom Headers

If you use web-based clients or need to handle cross-origin requests, it's important to include these headers in the ejabberd configuration to allow CORS.

---

## Multicore Processing

HMAC File Server now supports **multicore processing**. This allows the server to efficiently use all available CPU cores, improving performance, especially under high-load conditions. It uses Go's `GOMAXPROCS` to set the number of CPUs that can be used simultaneously.

To enable multicore processing, no additional configuration is required. The server automatically utilizes all available CPU cores:

```go
runtime.GOMAXPROCS(runtime.NumCPU())
```

---

## Monitoring with Prometheus

The HMAC File Server exposes metrics that can be scraped by Prometheus for monitoring. Ensure the metrics endpoint is enabled in the configuration.

### Example Metrics Endpoint

Access the metrics at the configured port:

```
http://localhost:9090/metrics
```

This will provide various metrics related to the HMAC File Server's performance and resource usage.

---

## Ensuring SOCKS Proxy Usage

To ensure that the `hmac-file-server` uses a SOCKS proxy, you can configure the environment to route requests through a SOCKS proxy server.

### Steps:

1. Install **proxychains** (or another proxy utility) on your system:

```bash
sudo apt-get install proxychains
```

2. Configure `proxychains` to use your SOCKS proxy. Edit the configuration file at `/etc/proxychains.conf`:

```bash
nano /etc/proxychains.conf
```

Add or update the following at the end of the file to point to your SOCKS proxy server:

```conf
socks5  127.0.0.1 9050  # Example SOCKS5 proxy running on localhost and port 9050
```

3. Start the `hmac-file-server` using `proxychains`:

```bash
proxychains ./hmac-file-server --config=config.toml
```

This will route all traffic through the configured SOCKS proxy.

---

## Acknowledgements

A huge thanks to **Thomas Leister** for providing inspiration and the foundation for the development of this project. His work has been invaluable in shaping the functionality and design of the `hmac-file-server`.

---