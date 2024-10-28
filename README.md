
# HMAC File Server - v2.0.2

**Secure File Handling with HMAC Authentication**

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
    git clone https://github.com/yourusername/hmac-file-server.git
    cd hmac-file-server
    ```

3. **Build the Server**

    ```bash
    go build -o hmac-file-server main.go
    ```

---

## Configuration

Die Serverkonfiguration erfolgt über eine `config.toml`-Datei. Unten findest du ein Beispiel für eine Konfigurationsdatei mit Erklärungen zu den einzelnen Einstellungen.

```toml
# Server listening configuration
ListenPort = ":8080"                  # Port to listen on (e.g., ":8080" for TCP)
UnixSocket = false                    # Set to true to use a Unix socket instead of TCP

# Security configuration
Secret = "your-very-secure-secret-key" # HMAC secret key for authentication

# File storage configuration
StoreDir = "./uploads"                # Directory to store uploaded files
UploadSubDir = "files"                # Subdirectory for file uploads

# Logging configuration
LogLevel = "info"                      # Logging level (e.g., "debug", "info", "warn", "error")
LogFile = "./server.log"              # Path to the log file (optional)

# Metrics configuration
MetricsEnabled = true                  # Enable Prometheus metrics
MetricsPort = ":9090"                  # Port for the metrics server

# File management
FileTTL = "30d"                        # Time-to-live for files before expiration (optional)
ResumableUploadsEnabled = true         # Enable resumable uploads
ResumableDownloadsEnabled = true       # Enable resumable downloads
EnableVersioning = true                # Enable file versioning
MaxVersions = 5                        # Maximum number of file versions to keep

# Chunking configuration
ChunkingEnabled = true                 # Enable chunked uploads
ChunkSize = 1048576                    # Size of each chunk in bytes (1MB)
```

---

