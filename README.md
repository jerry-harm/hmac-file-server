
# HMAC File Server

HMAC File Server is a file handling server for uploading and downloading files, designed with security in mind. It verifies HMAC signatures to ensure secure file transfers, provides retry mechanisms for file access, and includes configurable options to control server behavior such as logging levels, retry delays, and maximum retry attempts.

## Key Features
- **HMAC-based file transfers**: Ensure that only authenticated users can upload/download files.
- **Rate-limiting & Auto-banning**: Prevent abuse by rate-limiting access after multiple failed attempts and support for automatic unbanning.
- **File retry mechanism**: Retries file access multiple times before giving up, which is useful for large file systems.
- **Disk space checks**: Prevents uploading when the storage space is critically low.
- **Cross-Origin Resource Sharing (CORS)**: Built-in support for CORS headers.
- **Support for Unix sockets**: Allows communication over Unix domain sockets for improved performance.
- **Graceful shutdown**: Supports clean server shutdown when receiving termination signals (`SIGINT`, `SIGTERM`).
- **HTTP/2 support**: Enhanced performance for uploads and downloads with HTTP/2.

## New Improvements (v1.0):
- **Graceful Shutdown**: Server now handles shutdowns gracefully, ensuring no incomplete transfers during shutdown.
- **HTTP/2 Support**: HTTP/2 support is added, improving performance for concurrent file uploads and downloads.
- **Rate-Limiting Enhancements**: Rate-limiting and banning use `sync.Map` for better concurrency management.
- **Improved Structured Logging**: We now use structured logging (`logrus.Fields`) for more detailed and helpful logs.
- **Config Defaults**: We’ve set sensible default values for configuration items like `ListenPort`, `MaxRetries`, and `RetryDelay` to reduce errors from incomplete configuration files.
- **Retries for GET requests**: Added an option to enable retry logic for GET requests in case of file access delays.

## Configuration
The configuration is done via a TOML file, which is passed to the server as a startup argument.

Example `config.toml`:

```toml
ListenPort = "8080"
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
```

### Notable Configuration Parameters:
- `ListenPort`: Port where the server listens (default: 8080).
- `Secret`: The HMAC secret key used for file authentication.
- `StoreDir`: Directory to store uploaded files.
- `LogLevel`: The level of logging (options: `debug`, `info`, `warn`, `error`).
- `MaxRetries`: Number of retries for file retrieval on GET requests.
- `RetryDelay`: Delay between retries for file retrieval (in seconds).
- `AutoUnban`: Automatically unban a blocked path after a specified duration.
- `AutoBanTime`: Time (in seconds) for which a path is banned after exceeding failed attempts.

## Usage
You can run the `hmac-file-server` server by providing the path to your configuration file:

```bash
./hmac-file-server --config=config.toml
```

### Command-line Options:
- `--config`: Specify the path to the configuration file (default: `./config.toml`).
- `--help`: Display the help message and exit.
- `--version`: Show the version of the program and exit.

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

## Verifying Service Status:
To verify if the `hmac-file-server` is running correctly, you can check the `systemd` logs. Run the following command:

```bash
sudo systemctl status hmac-file-server.service
```

You should see output similar to the following if the service is running successfully:

```
Oct 14 09:38:42 nginxsslh.uuxo.net systemd[1]: Started hmac-file-server.service - HMAC File Server - Secure File Handling Server.
Oct 14 09:38:42 nginxsslh.uuxo.net hmac-file-server[1154221]: time="2024-10-14T09:38:42Z" level=info msg="Starting hmac-file-server c97fa66 ..."
Oct 14 09:38:42 nginxsslh.uuxo.net hmac-file-server[1154221]: time="2024-10-14T09:38:42Z" level=info msg="Server started on port [::1]:5050. Waiting for requests."
```

## Dependencies
- [BurntSushi/toml](https://github.com/BurntSushi/toml) - TOML parser for Go.
- [Sirupsen/logrus](https://github.com/sirupsen/logrus) - Structured, pluggable logging for Go.

## License
HMAC File Server is licensed under the MIT License. See `LICENSE` for more details.

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
ExecStart=/home/hmac-file-server/hmac-file-server --config=/home/hmac-file-server/config.toml
WorkingDirectory=/home/hmac-file-server
Restart=on-failure
User=hmac-file-server
Group=hmac-file-server
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

Thanks to Thomas Leister for providing the base and inspiration for Prosody Filer.
