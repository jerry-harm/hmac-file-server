
# HMAC File Server

## Overview
The HMAC File Server is a secure file handling server that supports HMAC authentication. It offers features like chunked uploads, file versioning, resumable uploads, Redis caching, and Prometheus metrics for monitoring.

## Features
- **HMAC Authentication**: Secure file uploads and downloads.
- **Chunked Uploads**: Supports large files by breaking them into smaller chunks.
- **Redis Caching**: Utilizes Redis for caching upload metadata, with fallback to internal storage.
- **Dynamic CPU Configuration**: Manages CPU resources effectively.
- **File Versioning**: Maintains multiple versions of uploaded files.
- **File TTL**: Automatically deletes files after a specified time period.
- **Resumable Uploads**: Allows for resuming interrupted uploads.
- **Health Checks**: Monitors server health status.
- **Garbage Collection**: Cleans up old versions to manage storage efficiently.
- **Prometheus Metrics**: Exposes server metrics for monitoring.

![image](https://github.com/user-attachments/assets/d7a4a0d6-9782-40f0-8b9c-8cdf1572ef03)

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd hmac-file-server
   ```

2. Build the server:
   ```bash
   go build -o hmac-file-server
   ```

3. Create a configuration file named `config.toml` in the same directory as the server executable.

## Configuration (config.toml)
The following parameters are available in the `config.toml` file:

```toml
# Server Configuration
ListenPort = ":8080"                    # Port for the server to listen on
UnixSocket = false                        # Use Unix socket instead of TCP
Secret = "your-secret-key"               # HMAC secret key for authentication
StoreDir = "/path/to/store"              # Directory where files will be stored
UploadSubDir = "uploads"                 # Subdirectory for uploads
LogLevel = "info"                        # Logging level (options: debug, info, warn, error)
LogFile = "/path/to/logfile.log"         # Log file path; leave empty for stdout
MetricsEnabled = true                     # Enable Prometheus metrics
MetricsPort = ":9090"                    # Port for Prometheus metrics
FileTTL = "30d"                          # Time to live for uploaded files (e.g., 30d, 1h)
ChunkingEnabled = true                    # Enable chunked uploads
ChunkSize = 1048576                       # Size of each chunk in bytes (1MB)
ResumableUploadsEnabled = true            # Enable resumable uploads
EnableVersioning = true                   # Enable file versioning
MaxVersions = 5                           # Maximum number of versions to keep
```

## Running the Server

To run the server, use the following command:
```bash
./hmac-file-server -config ./config.toml
```

## API Endpoints

- **Upload File**: `PUT /uploads/<file-name>`
  - Use HMAC authentication with query parameters for versioning.
  - Supports resumable uploads if enabled.

- **Download File**: `GET /uploads/<file-name>`
  - Retrieves the requested file.

- **File Metadata**: `HEAD /uploads/<file-name>`
  - Returns metadata of the specified file.

- **Metrics**: `GET /metrics`
  - Exposes Prometheus metrics.

## License
This project is licensed under the MIT License.

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for any features or bug fixes.
