
# HMAC File Server

## Overview
This is a secure file server that uses HMAC-based authentication for secure file handling. The server supports multiple protocols (`v`, `v2`, `token`) and integrates features like chunked uploads, rate limiting, Redis, PostgreSQL, and MySQL fallback support. Prometheus metrics are available to monitor server performance.

## Features
- **HMAC Authentication**: Supports multiple versions of HMAC-based authentication (`v`, `v2`, `token`).
- **Chunked Uploads**: Handles large file uploads through chunking.
- **Rate Limiting**: Supports configurable upload rate limiting.
- **Fallback Databases**: Supports Redis as the primary store and fallback options for PostgreSQL or MySQL.
- **Prometheus Metrics**: Exposes Prometheus metrics for monitoring upload durations and errors.
- **CORS Support**: Adds CORS headers for cross-origin support.

## Installation

### Prerequisites
- Go 1.16 or later
- Redis (optional)
- PostgreSQL or MySQL (optional)
- Prometheus (optional, for metrics)

### Clone Repository
```bash
git clone https://github.com/your-repo/hmac-file-server.git
cd hmac-file-server
```

### Build
To build the server:
```bash
go build -o hmac-file-server main.go
```

### Configuration
Create a `config.toml` file with the following structure:
```toml
ListenPort = ":8080"
UnixSocket = false
Secret = "your-hmac-secret"
StoreDir = "/path/to/store"
UploadSubDir = "upload"
LogLevel = "info"
LogFile = "/path/to/log/file.log"

# Redis configuration (optional)
RedisAddr = "localhost:6379"
RedisPassword = ""
RedisDB = 0

# Fallback Database (optional)
FallbackEnabled = true
FallbackDBType = "postgres" # or "mysql"
FallbackDBHost = "localhost"
FallbackDBUser = "dbuser"
FallbackDBPassword = "dbpassword"
FallbackDBName = "dbname"

# Metrics (optional)
MetricsEnabled = true
MetricsPort = ":9090"

# Upload settings
ChunkSize = 1048576  # 1 MB
UploadMaxSize = 1073741824  # 1 GB
MaxBytesPerSecond = 524288  # 512 KB/s
```

### Running the Server
Start the server by providing the path to your `config.toml`:
```bash
./hmac-file-server -config ./config.toml
```

### Prometheus Metrics
If enabled, you can access metrics at `/metrics` on the configured `MetricsPort`.

![image](https://github.com/user-attachments/assets/c735fdd6-e33d-49e0-ac3f-9f697df6689a)

### Example of HMAC Authentication
For `v` protocol:
```bash
hmac-sha256("file/path 1024")
```

For `v2` or `token` protocol:
```bash
hmac-sha256("file/path\x00content-length\x00content-type")
```

# Changes in the HMAC File Server

## 1. Manual Garbage Collection
- A new function `startPeriodicGarbageCollection` has been added.
- It triggers the garbage collector manually every 30 seconds to ensure periodic cleanup of unused memory.
- The function is as follows:

```go
func startPeriodicGarbageCollection() {
    ticker := time.NewTicker(30 * time.Second) // Adjust the interval as needed
    defer ticker.Stop()

    for range ticker.C {
        log.Info("Running manual garbage collection...")
        runtime.GC()
        log.Info("Garbage collection completed.")
    }
}
```

- This function is called as a goroutine in the `main` function.

```go
// Start periodic garbage collection
go startPeriodicGarbageCollection()
```

## 2. System Status Monitoring
- A new function `monitorSystemStatus` has been added to periodically log the status of the system (CPU, memory, and goroutines).
- This function runs every 10 seconds and provides insights into the system's state during runtime.

```go
func monitorSystemStatus() {
    ticker := time.NewTicker(10 * time.Second) // Adjust the interval as needed
    defer ticker.Stop()

    for range ticker.C {
        // Log the number of active goroutines
        numGoroutines := runtime.NumGoroutine()
        log.Infof("Active goroutines: %d", numGoroutines)

        // Log memory usage
        var memStats runtime.MemStats
        runtime.ReadMemStats(&memStats)
        log.Infof("Memory usage - Alloc: %v MB, TotalAlloc: %v MB, Sys: %v MB, NumGC: %v",
            memStats.Alloc/1024/1024, memStats.TotalAlloc/1024/1024, memStats.Sys/1024/1024, memStats.NumGC)

        // Log CPU usage
        cpuPercent, err := cpu.Percent(0, false)
        if err == nil && len(cpuPercent) > 0 {
            log.Infof("CPU usage: %.2f%%", cpuPercent[0])
        } else {
            log.Warn("Could not retrieve CPU usage information.")
        }
    }
}
```

- This function is also called as a goroutine in the `main` function.

```go
// Start monitoring system status (goroutines, memory, CPU)
go monitorSystemStatus()
```

## 3. Integration in `main` function
- The `main` function has been updated to include both periodic garbage collection and system status monitoring:

```go
func main() {
    // Setup logging
    setupLogging()
    fmt.Println("Logging setup completed.")

    // Start monitoring system status (goroutines, memory, CPU)
    go monitorSystemStatus()

    // Start periodic garbage collection
    go startPeriodicGarbageCollection()

    // Remaining code...
}
```

These changes ensure better resource management and monitoring during the server's runtime.

### License
This project is licensed under the MIT License.
