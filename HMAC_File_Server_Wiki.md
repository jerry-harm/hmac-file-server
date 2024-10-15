## Overview

HMAC File Server is a secure file handling server designed for use with XMPP servers like Prosody and ejabberd. It enables HMAC-based file uploads and downloads, rate limiting, auto-banning, auto-file deletion, multicore processing, and caching.

### Key Features
- **HMAC Authentication**: Secure file transfers using HMAC signatures.
- **Retry Mechanism**: Automatic retries for file access and downloads.
- **Disk Space Checks**: Prevents uploads if disk space is low.
- **Rate Limiting & Auto-Banning**: Protects against abuse by limiting failed access attempts.
- **Auto-File Deletion**: Automatically delete files older than a configurable period.
- **Multicore Support**: Efficiently uses all available CPU cores for optimized performance.
- **Caching**: In-memory caching to speed up file metadata handling.
- **HTTP/2 & CORS Support**: For faster and cross-origin file transfers.
- **Systemd Support**: Easily manage as a service.

---

## Configuration and Setup

The server is configured using a `config.toml` file. Below is a sample configuration:

```toml
ListenPort = "8080"
UnixSocket = false
Secret = "your-secret-key"
StoreDir = "/var/lib/hmac-file-server"
UploadSubDir = "uploads"
LogLevel = "info"
MaxRetries = 5
RetryDelay = 2
EnableGetRetries = true
BlockAfterFails = 5
BlockDuration = 300
AutoUnban = true
AutoBanTime = 600
DeleteFiles = true
DeleteFilesAfterPeriod = "30d"  # 30 days
WriteReport = true
ReportPath = "/var/log/hmac-file-server/deleted-files-report.log"
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
    max_size = 536870912 -- 512MB max upload size
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
- **`max_size`**: Maximum file size for uploads (set to 512MB).
- **`docroot`**: The local directory where uploaded files are stored.
- **`external_secret`**: Use the same HMAC secret as configured in `hmac-file-server`. Replace `"replace_with_hmac_file_server_secret"` with the actual secret.
- **`custom_headers`**: These headers are necessary if you're handling **cross-origin requests** (CORS), especially for web-based clients.

---

## ejabberd HTTP Upload Integration

For **ejabberd**, the HTTP file upload integration with HMAC File Server can be configured as shown below:

```yaml
mod_http_upload:
    max_size: 536870912  # 512MB max upload size
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
- **`max_size`**: Maximum size for file uploads (in bytes). The example is set to 512MB.

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

## Caching

The HMAC File Server also incorporates in-memory caching to improve performance, particularly for frequently accessed file metadata. This cache reduces file system reads and speeds up file retrieval times. The cache is configured to expire entries after a certain period and cleans up stale entries periodically.

The caching mechanism is enabled by default and requires no additional configuration. It uses Go’s `cache` package to maintain in-memory cache entries.

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