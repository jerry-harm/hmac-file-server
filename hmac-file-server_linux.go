package main

import (
    "context"
    "crypto/hmac"
    "crypto/sha256"
    "flag"
    "fmt"
    "io"
    "net"
    "net/http"
    "os"
    "os/signal"
    "path"
    "path/filepath"
    "runtime"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/BurntSushi/toml"
    "github.com/go-redis/redis/v8"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/sirupsen/logrus"
    "golang.org/x/sys/unix"
)

// Configuration structure for the server
type Config struct {
    ListenPort             string
    Secret                 string
    StoreDir               string
    LogLevel               string
    LogFile                string
    MaxRetries             int
    RetryDelay             int
    MetricsEnabled         bool
    MetricsPort            string
    RetentionPolicyEnabled bool
    MaxRetentionSize       int64
    MaxRetentionTime       string
    RedisAddr              string
    RedisPassword          string
    RedisDB                int
    HealthCheckInterval    int   // Interval for health checks
    MinFreeDiskSpace       int64 // Minimum disk space to maintain
}

var conf Config

var (
    // healthStatus is already declared, no need to redeclare it
    versionString = "1.0.5"
    minFreeSpaceThreshold int64 = 1073741824 // 1 GB
)

func init() {
    // Register Prometheus metrics
    prometheus.MustRegister(healthStatus)
}

// Setup logging based on configuration
func setupLogging() {
    if conf.LogFile != "" {
        file, err := os.OpenFile(conf.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
            log.Fatalf("Failed to open log file: %v", err)
        }
        log.Out = file
    } else {
        log.Out = os.Stdout
    }
    log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
    level, err := logrus.ParseLevel(conf.LogLevel)
    if err != nil {
        log.Warnf("Invalid log level: %s. Defaulting to 'info'.", conf.LogLevel)
        level = logrus.InfoLevel
    }
    log.SetLevel(level)
}

// Initialize Redis client
func InitRedisClient() (*redis.Client, error) {
    rdb := redis.NewClient(&redis.Options{
        Addr:     conf.RedisAddr,
        Password: conf.RedisPassword,
        DB:       conf.RedisDB,
    })

    _, err := rdb.Ping(ctx).Result()
    return rdb, err
}

// Check if the disk space is above the minimum free space threshold
func checkDiskSpace() bool {
    var stat unix.Statfs_t
    if err := unix.Statfs(conf.StoreDir, &stat); err != nil {
        log.Errorf("Error checking disk space: %v", err)
        return false
    }
    freeSpace := stat.Bavail * uint64(stat.Bsize)
    if freeSpace < minFreeSpaceThreshold {
        log.Warnf("Low disk space: %d bytes available, below threshold %d bytes", freeSpace, minFreeSpaceThreshold)
        return false
    }
    return true
}

// Check Redis health by pinging it
func checkRedisHealth() bool {
    if redisClient == nil {
        log.Warn("Redis client is not initialized")
        return false
    }
    _, err := redisClient.Ping(ctx).Result()
    if err != nil {
        log.Warnf("Redis health check failed: %v", err)
        return false
    }
    return true
}

// HealthCheck periodically checks the health of the server
func HealthCheck() {
    for {
        allHealthy := true

        // Check Redis health
        if !checkRedisHealth() {
            allHealthy = false
        }

        // Check disk space
        if !checkDiskSpace() {
            allHealthy = false
        }

        // Update Prometheus health status
        if allHealthy {
            healthStatus.Set(1)
            log.Info("Health check passed")
        } else {
            healthStatus.Set(0)
            log.Warn("Health check failed")
        }

        time.Sleep(time.Duration(conf.HealthCheckInterval) * time.Second)
    }
}

// Handle incoming requests (GET, PUT)
func handleRequest(w http.ResponseWriter, r *http.Request) {
    // Add CORS headers for cross-origin support
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, HEAD, GET, PUT")
    w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With, X-Session-Token")
    w.Header().Set("Access-Control-Allow-Credentials", "true")
    w.Header().Set("Access-Control-Max-Age", "7200")

    if r.Method == http.MethodOptions {
        w.WriteHeader(http.StatusNoContent)
        return
    }

    log.Infof("Handling request from IP: %s, Method: %s, URL: %s", r.RemoteAddr, r.Method, r.URL.Path)

    if r.Method == http.MethodPut {
        startTime := time.Now()

        sessionToken := r.Header.Get("X-Session-Token")
        if sessionToken == "" {
            sessionToken = strconv.FormatInt(time.Now().UnixNano(), 10)
            w.Header().Set("X-Session-Token", sessionToken)
        }

        dirPath := path.Join(conf.StoreDir, r.URL.Path)
        if err := os.MkdirAll(path.Dir(dirPath), 0755); err != nil {
            log.Errorf("Failed to create directory: %v", err)
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }

        outFile, err := os.OpenFile(dirPath, os.O_WRONLY|os.O_CREATE, 0644)
        if err != nil {
            log.Errorf("Failed to open file: %v", err)
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }
        defer outFile.Close()

        buffer := make([]byte, 65536) // 64KB buffer
        for {
            n, err := r.Body.Read(buffer)
            if err != nil && err != io.EOF {
                log.Errorf("Failed to read request body: %v", err)
                http.Error(w, "Internal Server Error", http.StatusInternalServerError)
                return
            }

            if n == 0 {
                break
            }

            if _, err := outFile.Write(buffer[:n]); err != nil {
                log.Errorf("Failed to write to file: %v", err)
                http.Error(w, "Internal Server Error", http.StatusInternalServerError)
                return
            }
        }

        duration := time.Since(startTime).Seconds()
        log.Infof("Upload completed in %.2f seconds for file %s", duration, dirPath)
        w.WriteHeader(http.StatusCreated)
    } else if r.Method == http.MethodGet {
        filePath := path.Join(conf.StoreDir, r.URL.Path)
        if _, err := os.Stat(filePath); os.IsNotExist(err) {
            log.Warnf("File not found: %s", filePath)
            http.Error(w, "Not Found", http.StatusNotFound)
            return
        }

        log.Infof("Serving file: %s", filePath)
        http.ServeFile(w, r, filePath)
    } else {
        http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
    }
}

// Custom duration parser to handle "d" (days) and "y" (years)
func parseCustomDuration(dur string) (time.Duration, error) {
    if strings.HasSuffix(dur, "y") {
        years, err := strconv.Atoi(strings.TrimSuffix(dur, "y"))
        if err != nil {
            return 0, err
        }
        return time.Duration(years) * 365 * 24 * time.Hour, nil
    } else if strings.HasSuffix(dur, "d") {
        days, err := strconv.Atoi(strings.TrimSuffix(dur, "d"))
        if err != nil {
            return 0, err
        }
        return time.Duration(days) * 24 * time.Hour, nil
    }
    return time.ParseDuration(dur)
}

// Function to read configuration from a file
func readConfig(filePath string) error {
    _, err := toml.DecodeFile(filePath, &conf)
    return err
}

// Main function to start the server, metrics, and health checks
func main() {
    var configFile string
    var showHelp bool
    var showVersion bool

    flag.StringVar(&configFile, "config", "./config.toml", "Path to configuration file.")
    flag.BoolVar(&showHelp, "help", false, "Display help message.")
    flag.BoolVar(&showVersion, "version", false, "Show the version of the program.")
    flag.Parse()

    if showHelp {
        fmt.Println("hmac-file-server version 1.0.0")
        fmt.Println("Usage: hmac-file-server [options]")
        os.Exit(0)
    }

    if showVersion {
        fmt.Println("hmac-file-server version 1.0.0")
        fmt.Println("Usage: hmac-file-server [options]")
        os.Exit(0)
    }

    if err := readConfig(configFile); err != nil {
        log.Fatalf("Failed to read configuration: %v", err)
    }

    setupLogging()

    redisClient, err := InitRedisClient()
    if err != nil {
        log.Warnf("Redis is unavailable: %v", err)
        redisClient = nil
    }

    // Start health checks in a separate goroutine
    go HealthCheck()

    listener, err := net.Listen("tcp", conf.ListenPort)
    if err != nil {
        log.Fatalf("Failed to open listener: %v", err)
    }

    srv := &http.Server{
        Addr:         conf.ListenPort,
        ReadTimeout:  1200 * time.Second,
        WriteTimeout: 1200 * time.Second,
    }

    if conf.MetricsEnabled {
        go func() {
            http.Handle("/metrics", promhttp.Handler())
            log.Printf("Metrics server listening on %s", conf.MetricsPort)
            if err := http.ListenAndServe(conf.MetricsPort, nil); err != nil {
                log.Fatalf("Metrics server failed: %v", err)
            }
        }()
    }

    http.HandleFunc("/", handleRequest)
    go func() {
        log.Printf("Server started on %s", conf.ListenPort)
        if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
            log.Fatalf("Server error: %v", err)
        }
    }()

    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    log.Println("Shutting down server...")
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    if err := srv.Shutdown(ctx); err != nil {
        log.Fatalf("Server forced to shutdown: %v", err)
    }
    log.Println("Server exited.")
}