
# HMAC File Server Configuration

This document provides a complete overview of the configuration options for the HMAC file server as defined in the `config.toml` file.

---

## Server Settings

- **ListenPort**: `":8080"`  
  Port for the file server to listen on.
  
- **UnixSocket**: `false`  
  Use Unix sockets if true; otherwise, TCP.

- **Secret**: `"example-hmac-secret"`  
  HMAC secret for securing uploads.

- **StoreDir**: `"/mnt/storage/hmac-file-server/"`  
  Directory for storing uploaded files.

- **UploadSubDir**: `"upload"`  
  Subdirectory for uploads.

- **LoggingEnabled**: `true`  
  Enable or disable logging.

- **LogLevel**: `"debug"`  
  Logging level: `"debug"`, `"info"`, `"warn"`, `"error"`.

- **LogFile**: `"/var/log/hmac-file-server.log"`  
  Path to the log file.

- **MetricsEnabled**: `true`  
  Enable Prometheus metrics.

- **MetricsPort**: `":9090"`  
  Port for the Prometheus metrics server.

---

## Encryption Settings

- **AESEnabled**: `true`  
  Enable AES encryption.

- **AESKey**: `"example-aes-key"`  
  AES encryption key.

---

## Workers and Connections

- **NumWorkers**: `5`  
  Number of workers handling uploads.

- **UploadQueueSize**: `50`  
  Queue size for handling multiple uploads.

---

## Graceful Shutdown

- **GracefulShutdownTimeout**: `60`  
  Timeout for graceful shutdowns (in seconds).

---

## File TTL

- **FileTTL**: `"365d"`  
  Time-to-live for file expiration.

- **ResumableUploadsEnabled**: `true`  
  Enable resumable uploads.

- **ResumableDownloads**: `true`  
  Enable resumable downloads.

- **MaxVersions**: `1`  
  Maximum number of file versions to keep.

- **EnableVersioning**: `false`  
  Enable or disable file versioning.

---

## Upload/Download Settings

- **ChunkedUploadsEnabled**: `true`  
  Enable or disable chunked uploads.

- **ChunkSize**: `8192`  
  Size of each upload chunk in bytes.

---

## Redis Settings

- **RedisEnabled**: `true`  
  Enable Redis for caching.

- **RedisAddr**: `"localhost:6379"`  
  Redis server address.

- **RedisPassword**: `""`  
  Redis password.

- **RedisDBIndex**: `0`  
  Redis database index.

- **RedisHealthCheckInterval**: `"120s"`  
  Interval for health checks.

---

## Server Timeout Settings

- **ReadTimeout**: `"4800s"`  
  Server read timeout.

- **WriteTimeout**: `"4800s"`  
  Server write timeout.

- **IdleTimeout**: `"4800s"`  
  Server idle timeout.

---

## ClamAV Configuration

- **ClamAVEnabled**: `true`  
  Enable ClamAV antivirus scanning.

- **NumScanWorkers**: `5`  
  Number of scan workers.

- **ClamAVSocket**: `"/var/run/clamav/clamd.ctl"`  
  ClamAV socket path.

---

## Security Settings

- **RateLimitingEnabled**: `false`  
  Enable or disable rate limiting.

- **MaxRequestsPerMinute**: `60`  
  Maximum number of requests per minute.

- **RateLimitInterval**: `"1m"`  
  Interval for rate limiting.

- **BlockedUserAgents**: `["MisskeyBot/1.0", "EvilCrawler"]`  
  List of blocked user agents.

---

## Fail2Ban

- **Enable**: `true`  
  Enable Fail2Ban.

- **Jail**: `"hmac-auth"`  
  Jail name for Fail2Ban.

- **BlockCommand**: `"/usr/bin/fail2ban-client set hmac-auth <IP>"`  
  Command to block IPs.

- **UnblockCommand**: `"/usr/bin/fail2ban-client set hmac-auth unban <IP>"`  
  Command to unblock IPs.

- **MaxRetries**: `3`  
  Maximum retries before banning.

- **BanTime**: `"3600s"`  
  Ban duration.

---

## IP Management Settings

- **EnableIPManagement**: `false`  
  Enable IP management.

- **AllowedIPs**: `["0.0.0.0/0"]`  
  List of allowed IP ranges.

- **IPCheckInterval**: `"65s"`  
  Interval for IP checks.

---

## IP Header/Log Parsing Settings

- **IPSource**: `"nginx-log"`  
  Source for IP logging: `"header"` or `"nginx-log"`.

- **NginxLogFile**: `"/var/log/nginx/stream-access.log"`  
  Required if `IPSource = "nginx-log"`.

---

## Allowed File Extensions

Allowed file extensions include:

- **Documents**: `.txt`, `.pdf`
- **Images**: `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`, `.tiff`, `.svg`, `.webp`
- **Videos**: `.wav`, `.mp4`, `.avi`, `.mkv`, `.mov`, `.wmv`, `.flv`, `.webm`, `.mpeg`, `.mpg`, `.m4v`, `.3gp`, `.3g2`
- **Audio**: `.mp3`, `.ogg`

---

## Deduplication Settings

- **DeduplicationEnabled**: `true`  
  Enable or disable deduplication based on checksum.
