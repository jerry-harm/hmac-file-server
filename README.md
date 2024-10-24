
# HMAC File Server

## Overview

The HMAC File Server is a secure file upload and download server that uses HMAC authentication to verify requests. It includes support for chunked uploads, Prometheus metrics, Redis, and fallback database options (PostgreSQL/MySQL).

## Features

- Secure file uploads with HMAC authentication
- Chunked uploads with support for resumable transfers
- Prometheus metrics integration
- Redis and fallback database support
- Configurable upload size and rate limits
- Graceful shutdown and garbage collection

## Usage

### Compilation

To build the HMAC File Server, you need to have Go installed. You can compile the server using the following commands:

```bash
git clone https://github.com/your-repo/hmac-file-server.git
cd hmac-file-server
go build -o hmac-file-server
```

### Configuration

The server configuration is done via a `config.toml` file. Below is an example of the configuration parameters:

```toml
ListenPort = ":8080"  
UnixSocket = false  
Secret = "stellar-wisdom-orbit-echo"  
StoreDir = "/mnt/storage/hmac-file-server/"  
UploadSubDir = "upload"  
LogLevel = "info"  
LogFile = "/var/log/hmac-file-server.log"  
MaxRetries = 5  
RetryDelay = 2  
MetricsEnabled = true  
MetricsPort = ":9090"  
ChunkSize = "64KB"  # Human-readable format
UploadMaxSize = "1GB"  # Human-readable format
MaxBytesPerSecond = "1MB/s"  # Human-readable format

# Redis configuration (optional)
RedisAddr = "localhost:6379"  
RedisPassword = ""  
RedisDB = 0  

# Fallback database configuration (optional)
FallbackEnabled = false  
FallbackDBType = "postgres"  
FallbackDBHost = "localhost"  
FallbackDBUser = "your_db_user"  
FallbackDBPassword = "your_db_password"  
FallbackDBName = "your_db_name"  

# Garbage Collection Intervall
GarbageCollectionInterval = "30s"  # Garbage collection interval in human-readable format

# Resources CPU/MEM
MaxWorkers = "auto"
MaxMemoryMB = "4GB"  # Human-readable format
```

### Helper for Configuration Issues

The server includes built-in validation for config parameters. If there is an issue with the configuration, the server will display an error message with advice on how to fix it.

### Running the Server

Once compiled, you can run the server using:

```bash
./hmac-file-server -config ./config.toml
```

### Prometheus Metrics

The following Prometheus metrics are exported by the server:

- `hmac_file_server_upload_duration_seconds`: Histogram of file upload duration in seconds
- `hmac_file_server_upload_errors_total`: Total number of file upload errors
- `hmac_file_server_uploads_total`: Total number of successful file uploads
- `hmac_file_server_download_duration_seconds`: Histogram of file download duration in seconds
- `hmac_file_server_download_errors_total`: Total number of file download errors
- `hmac_file_server_downloads_total`: Total number of successful file downloads
- `memory_usage_bytes`: Current memory usage in bytes
- `cpu_usage_percent`: Current CPU usage as a percentage
- `active_connections_total`: Total number of active connections
- `http_requests_total`: Total number of HTTP requests, labeled by method and path
- `goroutines_count`: Current number of goroutines

### Systemd Service

To run the server as a systemd service, create a service file at `/etc/systemd/system/hmac-file-server.service`:

```ini
[Unit]
Description=HMAC File Server
After=network.target

[Service]
Type=simple
ExecStart=/path/to/hmac-file-server -config /path/to/config.toml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl enable hmac-file-server
sudo systemctl start hmac-file-server
```

### NGINX Configuration

To use NGINX as a reverse proxy for the HMAC File Server:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Apache2 Configuration

For Apache2, use the following configuration:

```apache
<VirtualHost *:80>
    ServerName your-domain.com

    ProxyPass / http://localhost:8080/
    ProxyPassReverse / http://localhost:8080/

    RequestHeader set X-Forwarded-Proto "http"
    RequestHeader set X-Forwarded-Port "80"
</VirtualHost>
```

### ejabberd/Prosody Integration

For integrating with ejabberd or Prosody, you will need to configure mod_http_upload or mod_http_upload_external to use the HMAC File Server for secure file handling. You can configure the URL in your XMPP server configuration as follows:

#### ejabberd

```yaml
mod_http_upload_external:
  docroot: "/mnt/storage/hmac-file-server/"
  put_url: "https://your-domain.com/upload/"
  get_url: "https://your-domain.com/upload/"
  secret: "jasper-and-waldemar-are-wunderbar"
```

#### Prosody

```lua
Component "upload.your-domain.com" "http_upload_external"
    http_external_base_url = "https://your-domain.com/upload/"
    secret = "stellar-wisdom-orbit-echo"
```

## License

This project is licensed under the MIT License.
