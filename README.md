
# HMAC File Server

## Overview
HMAC File Server is a lightweight, secure file upload server that uses HMAC-based authentication for file handling and checksum verification for data integrity. It supports versioning, auto-deletion based on storage and age, and Prometheus metrics for monitoring.

## Features
- **HMAC Authentication**: Secure file uploads using HMAC-based authorization.
- **Checksum Verification**: Ensure file integrity using customizable checksum headers and algorithms.
- **File Versioning**: Keep multiple versions of uploaded files with customizable versioning strategies.
- **Auto-deletion**: Automatically delete files based on storage size limits or age.
- **Prometheus Metrics**: Monitor server performance and file operations using Prometheus.

## Configuration
The server can be configured via a `config.toml` file. Key options include:

- **Server Settings**: Configure the port, HMAC secret, and storage directories.
- **Checksum Verification**: Enable or disable checksum verification, and configure headers and algorithms.
- **Auto-Deletion and Retention**: Set limits for file retention based on storage size and file age.
- **Versioning**: Enable file versioning and configure the number of versions to retain.
- **Metrics**: Enable Prometheus metrics and set the metrics server port.

## Usage
To start the HMAC File Server:
```bash
./hmac-file-server -config ./config.toml
```

## Example Configuration (`config.toml`)
```toml
ListenPort = ":8080"
UnixSocket = false
Secret = "your-hmac-secret"
StoreDir = "/mnt/storage/hmac-file-server/"
UploadSubDir = "upload"

ChecksumVerification = true
ChecksumHeader = "X-Checksum"
ChecksumAlgorithm = "sha256"

MaxRetentionSize = 10737418240  # 10 GB
MaxRetentionTime = "30d"

EnableVersioning = true
VersioningDirectory = "/mnt/storage/hmac-file-server/versions/"
MaxVersions = 5
VersioningStrategy = "timestamp"

MetricsEnabled = true
MetricsPort = ":9090"
```

## License
MIT License
