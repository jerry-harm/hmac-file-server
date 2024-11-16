
# HMAC File Server

**Secure File Handling with HMAC Authentication**

![HMAC FILE SERVER](https://github.com/user-attachments/assets/77a85b5d-7104-4e1c-a21f-0233ca22a8db)

---

## Overview

The **HMAC File Server** is a robust and secure solution for handling file uploads and downloads. It leverages **HMAC authentication** to ensure that only authorized users can access or modify files. The server supports advanced features like **resumable uploads/downloads**, **file versioning**, **event-based network management**, and comprehensive **Prometheus metrics** for monitoring.

---

## Key Features

1. **HMAC Validation**
    - **Authentication Mechanism**: Validates requests using HMAC signatures to ensure secure access.
    - **Protocol Versions Support**: Supports multiple HMAC calculation protocols (`v`, `v2`, `token`) for flexibility.

2. **Event-Based Network Management**
    - **Event Types**: Handles events such as new connections, disconnections, request receptions, completions, errors, and shutdowns.
    - **Event Dispatcher**: Manages registration and dispatching of events to appropriate handlers asynchronously.

3. **Resumable Uploads and Downloads**
    - **Chunked Uploads**: Allows clients to upload large files in multiple chunks, enabling resumable uploads.
    - **Partial Downloads**: Supports HTTP `Range` headers to facilitate resumable downloads.

4. **File Versioning**
    - **Version Management**: Automatically versions existing files before overwriting, maintaining a history of changes.
    - **Cleanup Mechanism**: Removes older versions when exceeding the configured maximum to conserve storage.

5. **Prometheus Metrics Integration**
    - **Comprehensive Metrics**: Tracks uploads/downloads, errors, system resource usage, active connections, and more.
    - **Metrics Endpoint**: Exposes metrics on the `/metrics` endpoint for Prometheus scraping.
  
6. **Graceful Shutdown**
    - **Signal Handling**: Listens for termination signals (`SIGINT`, `SIGTERM`) to initiate a graceful shutdown.
    - **Resource Cleanup**: Ensures all ongoing operations complete before terminating the server.

7. **Comprehensive Logging**
    - **Structured Logging**: Utilizes `logrus` for detailed and leveled logging.
    - **Event-Driven Logs**: Logs events like new connections, request handling, completions, and errors with contextual information.

---

## Installation

1. **Prerequisites**
    - **Go**: Ensure Go is installed on your system. [Download Go](https://golang.org/dl/)
    - **Dependencies**: The server uses several Go packages. They will be fetched automatically during the build process.

2. **Clone the Repository**

    ```bash
    git clone https://github.com/PlusOne/hmac-file-server.git
    cd hmac-file-server
    ```

3. **Build the Server**

    ```bash
    go build -o hmac-file-server main.go
    ```

---

## Configuration

The server configuration is managed via a `config.toml` file. Below is a sample configuration file with explanations for each setting, including the updated sections on security settings and Fail2Ban integration.

```toml
# Example configuration for HMAC File Server

# Server settings
ListenPort               = ":8080"                              # Port for the file server to listen on
UnixSocket               = false                                # Use Unix sockets if true, otherwise TCP
Secret                   = "your-secret-key"                    # HMAC secret for securing uploads
StoreDir                 = "/mnt/storage/hmac-file-server/"     # Directory for storing uploaded files
UploadSubDir             = "upload"                             # Subdirectory for uploads
LogLevel                 = "info"                               # Logging level: "debug", "info", "warn", "error"
LogFile                  = "/var/log/hmac-file-server.log"      # Log file path
MetricsEnabled           = true                                 # Enable Prometheus metrics
MetricsPort              = ":9090"                              # Port for Prometheus metrics server

# Workers and connections
NumWorkers               = 20                                   # Number of workers
UploadQueueSize          = 5000                                 # Upload queue size for handling multiple uploads

# Graceful shutdown
GracefulShutdownTimeout  = 60                                   # Timeout for graceful shutdowns (in seconds)

# File TTL and versioning
FileTTL                  = "90d"                                # TTL for file expiration
ResumableUploadsEnabled  = true                                 # Enable resumable uploads
ResumableDownloads       = true                                 # Enable resumable downloads
MaxVersions              = 3                                    # Maximum number of file versions to keep
EnableVersioning         = true                                 # Enable file versioning

# Upload/Download settings
ChunkedUploadsEnabled    = true                                 # Enable chunked uploads
ChunkSize                = 65536                                # Size of each chunk in bytes (64 KB)

# Redis settings
RedisEnabled             = true                                 # Enable Redis for caching
RedisAddr                = "localhost:6379"                     # Redis server address
RedisPassword            = ""                                   # Redis password (if any)
RedisDBIndex             = 1                                    # Redis DBIndex

# Server timeout settings
ReadTimeout              = "1h"                                 # Server read timeout
WriteTimeout             = "1h"                                 # Server write timeout
IdleTimeout              = "30m"                                # Server idle timeout

# ClamAV Configuration
ClamAVSocket             = "/var/run/clamav/clamd.ctl"          # Use UNIX socket; alternatively use TCP socket

# Allowed file extensions including image, video, and document formats
AllowedExtensions = [
    # Document formats
    ".txt", ".pdf",

    # Image formats
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".svg", ".webp",

    # Video formats
    ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".mpeg", ".mpg", ".m4v", ".3gp", ".3g2",

    # Audio formats
    ".mp3", ".ogg"
]

# Security settings
RateLimitingEnabled      = true                                 # Enable rate limiting
MaxRequestsPerMinute     = 60                                   # Maximum number of requests per minute
RateLimitInterval        = "1m"                                 # Rate limiting interval
BlockedUserAgents        = ["BadBot", "EvilCrawler"]            # List of blocked user agents

# Fail2Ban integration
Enable                    = true                                 # Enable or disable Fail2Ban integration
Jail                      = "hmac-auth"                          # Name of the jail to use in Fail2Ban
BlockCommand              = "/usr/bin/fail2ban-client set hmac-auth <IP>" # Command to block an IP
UnblockCommand            = "/usr/bin/fail2ban-client set hmac-auth unban <IP>" # Command to unblock an IP
MaxRetries                = 3                                    # Number of failed attempts before banning
BanTime                   = "3600s"                              # Duration for which the IP should be banned

# IP Management settings (optional)
EnableIPManagement       = false                                 # Enable IP management
AllowedIPs               = ["0.0.0.0/0"]                         # List of allowed IPs
IPCheckInterval          = "60s"                                 # Interval for IP check updates

# Deduplication settings
DeduplicationEnabled = true                                      # Enable/disable deduplication based on checksum
```
This configuration provides a detailed setup for the HMAC File Server, including how to handle security settings, limit rates, and integrate with system tools like Fail2Ban for enhanced security measures.
