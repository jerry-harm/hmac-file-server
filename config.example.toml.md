
# Configuration Example for HMAC File Server

This is an example configuration file for the HMAC File Server. You can customize the configuration options to suit your specific use case.

```toml
ListenPort = ":8080" # The port the server listens on.
UnixSocket = false # Use Unix Socket for communication.
Secret = "your-new-secret-here" # HMAC authentication secret.
StoreDir = "/mnt/storage/hmac-file-server/" # Directory for uploaded files.
UploadSubDir = "upload" # Subdirectory for uploads.
LogLevel = "debug" # Logging level.
LogFile = "/var/log/hmac-file-server.log" # Log file path.

EnableVersioning = true # Enable file versioning.
VersioningDirectory = "/mnt/storage/hmac-file-server/versions/" # Directory for versions.
MaxVersions = 5 # Maximum number of file versions to keep.
VersioningStrategy = "timestamp" # Versioning strategy.

MaxRetries = 5 # Maximum retries before banning a user.
RetryDelay = 2 # Delay between retries in seconds.
EnableGetRetries = true # Enable retries for GET requests.
MaxUploadSize = 1073741824 # Maximum upload size in bytes (1GB).
BufferSize = 65536 # Buffer size in bytes (64KB).
MinFreeSpaceThreshold = 104857600 # Minimum free space required (100MB).
BlockAfterFails = 5 # Block after this many failed attempts.
BlockDuration = 300 # Duration (in seconds) for which a client will be banned.
AutoUnban = true # Automatically unban clients after the ban duration expires.
AutoBanTime = 600 # Time (in seconds) after which clients will be automatically unbanned.

DeleteFiles = true # Enable automatic file deletion.
DeleteFilesAfterPeriod = "1y" # Period after which files will be deleted.
DeleteFilesReport = true # Enable reporting of deleted files.
DeleteFilesReportPath = "/home/hmac-file-server/deleted_files.log" # Path for delete report.

NumCores = "auto" # Number of CPU cores to use.
ReaskSecretEnabled = true # Enable periodic re-asking of the HMAC secret.
ReaskSecretInterval = "1h" # Time interval (in duration format) between secret re-asks.

MetricsEnabled = true # Enable Prometheus metrics.
MetricsPort = ":9090" # Port for Prometheus metrics.
```

## Configuration Options
- **ListenPort**: TCP port for the server.
- **UnixSocket**: Use Unix socket if true.
- **Secret**: HMAC secret key.
- **StoreDir**: Directory for uploaded files.
- **UploadSubDir**: Subdirectory for uploads.
- **LogLevel**: Log verbosity level.
- **MetricsEnabled**: Enable metrics for monitoring.
