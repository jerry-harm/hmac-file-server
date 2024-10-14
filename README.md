
# HMAC File Server

HMAC File Server is a file handling server for securely uploading and downloading files. It verifies HMAC signatures to ensure secure file transfers, provides retry mechanisms for file access, and includes configurable options to control server behavior such as logging levels, retry delays, maximum retry attempts, and auto-deletion of old files.

## Key Features

- **HMAC-based file transfers**: Ensure that only authenticated users can upload/download files.
- **Rate-limiting & Auto-banning**: Prevent abuse by rate-limiting access after multiple failed attempts and support for automatic unbanning.
- **File retry mechanism**: Retries file access multiple times before giving up, which is useful for large file systems.
- **Disk space checks**: Prevents uploading when the storage space is critically low.
- **Cross-Origin Resource Sharing (CORS)**: Built-in support for CORS headers.
- **Support for Unix sockets**: Allows communication over Unix domain sockets for improved performance.
- **Graceful shutdown**: Supports clean server shutdown when receiving termination signals (`SIGINT`, `SIGTERM`).
- **HTTP/2 support**: Enhanced performance for uploads and downloads with HTTP/2.
- **Auto-deletion of files**: Automatically delete files older than a specified period based on the configuration.
- **Graceful shutdown**: The server will handle shutdowns gracefully, ensuring no incomplete transfers during shutdown.

## New Improvements (v1.0):
- **Graceful Shutdown**: Server now handles shutdowns gracefully, ensuring no incomplete transfers during shutdown.
- **HTTP/2 Support**: HTTP/2 support is added, improving performance for concurrent file uploads and downloads.
- **Rate-Limiting Enhancements**: Rate-limiting and banning use `sync.Map` for better concurrency management.
- **Improved Structured Logging**: We now use structured logging (`logrus.Fields`) for more detailed and helpful logs.
- **Retries for GET requests**: Added an option to enable retry logic for GET requests in case of file access delays.
- **Auto-deletion of files**: Support for auto-deleting files older than a specified time period, based on the configuration settings.

## Configuration
The configuration is done via a TOML file, which is passed to the server as a startup argument.

Example `config.toml`:

```toml
ListenPort = ":8080"
UnixSocket = false
Secret = "supersecretkey"
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
DeleteFiles = true                    # Enable automatic deletion of files
DeleteFilesAfterPeriod = "30d"         # Time period after which files are deleted (supports d for days, m for months, y for years)
DeleteReport = "/var/log/delete.log"   # Path where the deletion report will be saved
```

### Notable Configuration Parameters:
- `ListenPort`: Port where the server listens (default: 8080).
- `Secret`: The HMAC secret key used for file authentication.
- `StoreDir`: Directory to store uploaded files.
- `UploadSubDir`: Directory for file uploads (inside `StoreDir`).
- `LogLevel`: The level of logging (options: `debug`, `info`, `warn`, `error`).
- `MaxRetries`: Number of retries for file retrieval on GET requests.
- `RetryDelay`: Delay between retries for file retrieval (in seconds).
- `AutoUnban`: Automatically unban a blocked path after a specified duration.
- `AutoBanTime`: Time (in seconds) for which a path is banned after exceeding failed attempts.
- `DeleteFiles`: Boolean flag to enable or disable automatic file deletion.
- `DeleteFilesAfterPeriod`: The period after which files are deleted, e.g., `30d` for 30 days.
- `DeleteReport`: Path to the file where the report of deleted files will be logged.

## Usage
You can run the `hmac-file-server` server by providing the path to your configuration file:

```bash
./hmac-file-server --config=config.toml
```

### Command-line Options:
- `--config`: Specify the path to the configuration file (default: `./config.toml`).
- `--help`: Display the help message and exit.
- `--version`: Show the version of the program and exit.

### Auto-Deletion of Files:
The auto-deletion functionality allows for automatic deletion of files based on the time period specified in the `config.toml`. For example, if you set:

```toml
DeleteFilesAfterPeriod = "30d"
```

The server will automatically delete files older than 30 days and log a report of the deleted files to the path specified in `DeleteReport`.

### Graceful Shutdown:
The server will now handle `SIGINT` and `SIGTERM` signals and shut down gracefully, ensuring no data loss during an upload or download.

## Example:
Here’s an example command for running HMAC File Server with a custom configuration file:

```bash
./hmac-file-server --config=/path/to/your/config.toml
```

To test HTTP/2 support, you can use tools like `curl`:

```bash
curl -k --http2 -T /path/to/uploadfile https://example.com/uploads/yourfile
```

## Setting up HMAC File Server with systemd

To manage HMAC File Server as a service using systemd, create a systemd service unit file as shown below:

1. Create the service file:

```bash
sudo nano /etc/systemd/system/hmac-file-server.service
```

2. Add the following content to the file:

```ini
[Unit]
Description=HMAC File Server - Secure File Handling Server
After=network.target

[Service]
ExecStart=/path/to/hmac-file-server --config=/path/to/config.toml
WorkingDirectory=/path/to/working-directory
Restart=on-failure
User=your-user
Group=your-group
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
```

Make sure to replace `/path/to/hmac-file-server`, `/path/to/config.toml`, and `/path/to/working-directory` with the actual paths on your system.

3. Reload systemd, enable, and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable hmac-file-server.service
sudo systemctl start hmac-file-server.service
```

4. To check the status of the service:

```bash
sudo systemctl status hmac-file-server.service
```

This setup will allow you to manage HMAC File Server as a systemd service.

## License
HMAC File Server is licensed under the MIT License. See `LICENSE` for more details.
