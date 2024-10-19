
# HMAC File Server - Version 1.0.4

This version of the HMAC file server introduces several enhancements to improve performance, logging, error handling, and scalability without changing the HMAC validation logic or core functionality. Below are the key changes and improvements.

## Key Features

- **HMAC Authentication**: Secure file uploads using HMAC (Hash-based Message Authentication Code).
- **CORS Support**: Allows cross-origin requests for specific methods.
- **Prometheus Metrics**: Collects metrics like upload duration, total uploads, and errors.
- **Graceful Shutdown**: The server now supports graceful shutdown with a timeout, ensuring active connections are not abruptly terminated.
- **Request Timeout**: Implemented read, write, and idle timeouts to avoid hanging connections.
- **Enhanced Logging**: Structured logging using `logrus` for better observability.
- **Efficient File Streaming**: Improved file upload handling with `io.Copy` for efficient streaming of large files.
- **Rate Limiting**: Basic structure for rate limiting requests, preventing abuse or DoS-like behavior.

## Enhancements in Version 1.0.4

### 1. Graceful Shutdown
The server now supports graceful shutdown. When a termination signal (SIGINT, SIGTERM) is received, the server waits for 10 seconds to allow active requests to complete before shutting down.

**Key Changes:**
```go
quit := make(chan os.Signal, 1)
signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
<-quit
log.Println("Shutting down server...")
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

if err := srv.Shutdown(ctx); err != nil {
    log.Fatal("Server forced to shutdown:", err)
}
log.Println("Server exiting")
```

### 2. Request Timeouts
To improve server performance and avoid slow clients from hanging the server, we added read, write, and idle timeouts to the HTTP server configuration.

**Key Changes:**
```go
srv := &http.Server{
    Addr:         address,
    ReadTimeout:  10 * time.Second,
    WriteTimeout: 10 * time.Second,
    IdleTimeout:  120 * time.Second,
}
```

### 3. Enhanced Logging
We now use structured logging with `logrus.WithFields` to add more context to each log entry. This helps in debugging by providing useful metadata such as the client IP address, HTTP method, and file path.

**Key Changes:**
```go
log.WithFields(logrus.Fields{
    "method": r.Method,
    "path":   r.URL.Path,
    "ip":     r.RemoteAddr,
}).Info("Handling request")
```

### 4. Efficient File Upload Handling
The file upload mechanism was improved by replacing `ioutil.ReadAll` with `io.Copy`, which streams the file data directly into the target file. This reduces memory usage, especially for large file uploads.

**Key Changes:**
```go
file, err := os.Create(filePath)
if err != nil {
    log.Errorf("Error creating file: %v", err)
    http.Error(w, "Internal Server Error", http.StatusInternalServerError)
    uploadErrorsTotal.Inc()
    return
}
defer file.Close()

if _, err := io.Copy(file, r.Body); err != nil {
    log.Errorf("Error copying body to file: %v", err)
    http.Error(w, "Internal Server Error", http.StatusInternalServerError)
    uploadErrorsTotal.Inc()
    return
}
```

### 5. Prometheus Metrics
The existing Prometheus metrics have been maintained and continue to monitor key aspects of the server’s performance, including:
- Number of goroutines
- File upload duration
- Number of successful uploads
- Number of upload errors

### 6. Configuration Validation
Improved configuration validation to prevent the server from starting with invalid settings. This ensures a more robust startup process.

**Key Changes:**
```go
err := readConfig(configFile, &conf)
if err != nil {
    log.Fatalln("Error reading configuration file:", err)
}
```

## Configuration Options

Below are the key configuration options:

```toml
# Example config.toml
ListenPort             = ":8080"        # HTTP listening port
UnixSocket             = false          # Enable Unix socket instead of TCP
UnixSocketPath         = "/tmp/hmac.sock" # Unix socket path (if UnixSocket = true)
Secret                 = "your-hmac-secret" # HMAC secret
StoreDir               = "/mnt/storage/hmac-file-server/" # Directory for storing files
UploadSubDir           = "upload"       # Subdirectory for uploads
LogLevel               = "info"         # Logging level (e.g., debug, info, warn, error)
LogFile                = "/var/log/hmac-file-server.log" # Log file path
MaxRetries             = 5              # Max retry attempts for failed uploads
RetryDelay             = 2              # Retry delay (in seconds) between attempts
EnableGetRetries       = true           # Enable retries for GET requests
BlockAfterFails        = 5              # Block IP after this many failed attempts
BlockDuration          = 300            # Block duration in seconds
AutoUnban              = true           # Enable auto unban of blocked IPs
AutoBanTime            = 600            # Time in seconds after which the ban will be lifted
DeleteFiles            = true           # Enable automatic deletion of files
DeleteFilesAfterPeriod = "1y"           # Period after which files will be deleted (e.g., 1y for 1 year)
WriteReport            = true           # Enable writing of delete report
ReportPath             = "/home/hmac-file-server/deleted_files.log" # Path to delete report
NumCores               = "auto"         # Number of CPU cores to use ("auto" to use all)
ReaskSecretEnabled     = true           # Enable secret re-asking
ReaskSecretInterval    = "1h"           # Interval to re-ask for the secret
MetricsEnabled         = true           # Enable Prometheus metrics
MetricsPort            = ":9090"        # Port for Prometheus metrics
```

## Running the Server

To start the server with the default configuration file:

```bash
./hmac-file-server --config ./config.toml
```

### Available Flags

- `--help`: Show usage information.
- `--version`: Display the version of the server.

## Conclusion

This update brings significant improvements to the server's robustness, performance, and security, while keeping the core HMAC functionality unchanged. The enhancements ensure smoother operations, easier debugging, and better scalability for production environments.
