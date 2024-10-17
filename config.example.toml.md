
# Configuration Example for HMAC File Server

This is an example configuration file for the HMAC File Server.

```toml
ListenPort = ":8080" # The port the server listens on.
UnixSocket = false # Use Unix Socket for communication.
UnixSocketPath = "/tmp/hmac-file-server.sock" # Path for Unix Socket.
Secret = "your-secret-here" # HMAC authentication secret.
StoreDir = "/mnt/storage/hmac-file-server" # Directory for uploaded files.
UploadSubDir = "uploads" # Subdirectory for uploads.
LogLevel = "info" # Logging level.
LogFile = "/var/log/hmac-file-server.log" # Log file path.
EnableVersioning = true # Enable file versioning.
VersioningDirectory = "/mnt/storage/hmac-file-server/versions/" # Directory for versions.
MaxVersions = 5 # Maximum number of file versions to keep.
MaxRetries = 5 # Maximum retries before banning a user.
RetryDelay = 2 # Delay between retries in seconds.
DeleteFiles = true # Enable automatic file deletion.
DeleteFilesAfterPeriod = "24h" # Period after which files are deleted.
MetricsEnabled = true # Enable Prometheus metrics.
MetricsPort = ":9090" # Port for Prometheus metrics.
MaxUploadSize = 1073741824 # Maximum upload size in bytes (1GB).
BufferSize = 65536 # Buffer size in bytes (64KB).
```

## Configuration Options
- **ListenPort**: TCP port for the server.
- **UnixSocket**: Use Unix socket if true.
- **Secret**: HMAC secret key.
- **StoreDir**: Directory for uploaded files.
- **LogLevel**: Log verbosity level.
- **MetricsEnabled**: Enable metrics for monitoring.
