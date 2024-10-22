package main

import (
<<<<<<< HEAD
	"bufio"
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

	_ "net/http/pprof" // pprof for profiling

	"github.com/BurntSushi/toml"
	"github.com/go-redis/redis/v8"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
=======
    "context"
    "crypto/hmac"
    "crypto/sha256"
    "flag"
    "fmt"
    "net"
    "net/http"
    "os"
    "os/signal"
    "runtime"
    "strconv"
    "sync"
    "syscall"
    "time"

    "github.com/BurntSushi/toml"
    "github.com/go-redis/redis/v8"
    "github.com/patrickmn/go-cache"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/sirupsen/logrus"
>>>>>>> origin/main
)

// Configuration of this server
type Config struct {
    ListenPort             string
    UnixSocket             bool
    UnixSocketPath         string
    Secret                 string
    StoreDir               string
    LogLevel               string
    LogFile                string
    MaxRetries             int
    RetryDelay             int
    EnableGetRetries       bool
    DeleteFiles            bool
    DeleteFilesAfterPeriod string
    WriteReport            bool
    ReportPath             string
    NumCores               string
    ReaskSecretEnabled     bool
    ReaskSecretInterval    string
    MetricsEnabled         bool
    MetricsPort            string
    ChecksumVerification   bool
    RetentionPolicyEnabled bool
    MaxRetentionSize       int64
    MaxRetentionTime       string
    RedisEnabled           bool   // New field to enable Redis check
    RedisAddr              string // Redis server address (e.g., "localhost:6379")
    RedisPassword          string // Redis password
    RedisDB                int    // Redis database number
    ReadTimeout            int    `toml:"read_timeout"`  // Read timeout in seconds
    WriteTimeout           int    `toml:"write_timeout"` // Write timeout in seconds
    BufferSize             int    `toml:"buffer_size"`   // Buffer size for reading file chunks

    // New settings for chunked uploads
    ChunkSize       int `toml:"chunk_size"`       // Size of each chunk in bytes
    ChunkMaxRetries int `toml:"chunk_max_retries"` // Maximum number of retries for failed chunks
}

var conf = Config{
    ListenPort:             ":8080",
    MaxRetries:             5,
    RetryDelay:             2,
    ReaskSecretEnabled:     true,
    ReaskSecretInterval:    "24h",
    MetricsEnabled:         true,
    MetricsPort:            ":9090",
    ChecksumVerification:   true,
    RetentionPolicyEnabled: true,
    MaxRetentionSize:       10737418240, // Default 10 GB
    MaxRetentionTime:       "30d",       // Default 30 days
    ReadTimeout:            1200,        // Increased timeout for Android clients (20 minutes)
    WriteTimeout:           1200,        // Increased timeout for Android clients (20 minutes)
    BufferSize:             65536,       // Default 64 KB buffer size
    RedisEnabled:           true,        // Default is true for Redis, can be disabled in config.toml

    // Default settings for chunked uploads
    ChunkSize:       1024 * 1024, // Default 1 MB chunk size
    ChunkMaxRetries: 3,           // Default 3 retries for failed chunks
}

var versionString string = "1.0.5"
var log = logrus.New()

// Redis client and context
var redisClient *redis.Client
var ctx = context.Background()

// Initialize an in-memory cache with default expiration and cleanup interval.
var fileMetadataCache = cache.New(5*time.Minute, 10*time.Minute)

// Pool for reusable HMAC instances
var hmacPool = sync.Pool{
    New: func() interface{} {
        return hmac.New(sha256.New, []byte(conf.Secret))
    },
}

// Prometheus metrics with "hmac_" prefix
var (
    goroutines = prometheus.NewGauge(prometheus.GaugeOpts{
        Namespace: "hmac",
        Name:      "file_server_goroutines",
        Help:      "Number of goroutines that currently exist in the HMAC File Server.",
    })

    uploadDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
        Namespace: "hmac",
        Name:      "file_server_upload_duration_seconds",
        Help:      "Histogram of file upload duration in seconds.",
        Buckets:   prometheus.DefBuckets,
    })

    uploadErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
        Namespace: "hmac",
        Name:      "file_server_upload_errors_total",
        Help:      "Total number of file upload errors.",
    })

    uploadsTotal = prometheus.NewCounter(prometheus.CounterOpts{
        Namespace: "hmac",
        Name:      "file_server_uploads_total",
        Help:      "Total number of successful file uploads.",
    })
)

func init() {
    // Register metrics
    prometheus.MustRegister(goroutines, uploadDuration, uploadErrorsTotal, uploadsTotal)
}

// Optimized Redis Client Initialization
func InitRedisClient() (*redis.Client, error) {
<<<<<<< HEAD
	rdb := redis.NewClient(&redis.Options{
		Addr:         conf.RedisAddr,     // Redis server address
		Password:     conf.RedisPassword, // Redis password, leave empty for no password
		DB:           conf.RedisDB,       // Redis database number
		PoolSize:     20,                 // Optimized connection pool size
		MinIdleConns: 10,                 // Minimum idle connections
	})
=======
    rdb := redis.NewClient(&redis.Options{
        Addr:     conf.RedisAddr,     // Redis server address
        Password: conf.RedisPassword, // Redis password, leave empty for no password
        DB:       conf.RedisDB,       // Redis database number
    })
>>>>>>> origin/main

    // Test the connection
    _, err := rdb.Ping(ctx).Result()
    if err != nil {
        return nil, err
    }

    return rdb, nil
}

// Check Redis connection and log the result
func checkRedisConnection() {
    if conf.RedisEnabled {
        log.Info("Checking Redis connection...")
        _, err := redisClient.Ping(ctx).Result()
        if err != nil {
            log.Warnf("Failed to connect to Redis at %s: %v", conf.RedisAddr, err)
        } else {
            log.Infof("Successfully connected to Redis at %s", conf.RedisAddr)
        }
    } else {
        log.Info("Redis is disabled in the configuration.")
    }
}

// Optimized Logging Setup (Buffered Logging)
func setupLogging() {
<<<<<<< HEAD
	if conf.LogFile != "" {
		file, err := os.OpenFile(conf.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		writer := bufio.NewWriter(file)
		log.SetOutput(writer)
	} else {
		log.SetOutput(os.Stdout)
	}
	log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	level, err := logrus.ParseLevel(conf.LogLevel)
	if err != nil {
		log.Warnf("Invalid log level: %s. Defaulting to 'info'.", conf.LogLevel)
		level = logrus.InfoLevel
	}
	log.SetLevel(level)
=======
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
>>>>>>> origin/main
}

// Reads the configuration file
func readConfig(configFile string, config *Config) error {
    _, err := toml.DecodeFile(configFile, config)
    return err
}

<<<<<<< HEAD
// EnsureDirectoryExists checks if a directory exists, and if not, creates it.
func EnsureDirectoryExists(dirPath string) error {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		log.Infof("Directory does not exist, creating: %s", dirPath)
		err := os.MkdirAll(dirPath, 0755)
		if err != nil {
			log.Errorf("Error creating directory: %s, error: %v", dirPath, err)
			return err
		}
	}
	return nil
}

// Generates a session token
func generateSessionToken() string {
	return strconv.FormatInt(time.Now().UnixNano(), 10) // Simple session token based on timestamp
}

// Allowed HTTP methods for CORS
var ALLOWED_METHODS = strings.Join([]string{
	http.MethodOptions,
	http.MethodHead,
	http.MethodGet,
	http.MethodPut,
}, ", ")

// CORS headers function
func addCORSheaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", ALLOWED_METHODS)
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With, X-Session-Token")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "7200")
}

// Optimized Redis Session Management with Context
func manageSession(r *http.Request) (string, error) {
	// Get or generate a session token
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sessionToken := r.Header.Get("X-Session-Token")
	if sessionToken == "" {
		sessionToken = generateSessionToken() // Generate a new session token
	}

	// If Redis is available, store the session in Redis
	if redisClient != nil {
		err := redisClient.Set(ctx, fmt.Sprintf("session:%s", sessionToken), sessionToken, 24*time.Hour).Err()
		if err != nil {
			log.Warnf("Error storing session in Redis: %v", err)
			return "", err
		}
	} else {
		// Fall back to in-memory cache
		fileMetadataCache.Set(fmt.Sprintf("session:%s", sessionToken), sessionToken, cache.DefaultExpiration)
	}

	return sessionToken, nil
}

// Retry function to restart failed subroutines with exponential backoff
func retryUpload(ctx context.Context, maxRetries int, retryDelay int, uploadFunc func() error) error {
	var attempt int
	for {
		err := uploadFunc()
		if err == nil {
			return nil
		}

		attempt++
		if attempt >= maxRetries {
			log.Errorf("Upload failed after %d attempts: %v", attempt, err)
			return err
		}

		// Exponential backoff for retry delay
		delay := time.Duration(retryDelay*(1<<attempt)) * time.Second
		log.Warnf("Upload failed, retrying in %v (attempt %d/%d)", delay, attempt, maxRetries)
		time.Sleep(delay)
	}
}

// Request handler with self-healing function for upload retries
=======
// Handler function for HTTP requests
>>>>>>> origin/main
func handleRequest(w http.ResponseWriter, r *http.Request) {
    // Placeholder logic for handling HTTP requests
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Request handled successfully!"))
}

// Deletes old files based on retention policy
func deleteOldFiles() error {
    // Placeholder logic for deleting old files
    log.Info("Deleting old files based on retention policy...")
    return nil
}

// Main function with Redis check, graceful shutdown, request timeout, and metrics
func main() {
    var configFile string
    var showHelp bool
    var showVersion bool
    var proto string

    flag.StringVar(&configFile, "config", "./config.toml", "Path to configuration file \"config.toml\".")
    flag.BoolVar(&showHelp, "help", false, "Display this help message")
    flag.BoolVar(&showVersion, "version", false, "Show the version of the program")

    flag.Parse()

    if showHelp {
        fmt.Println("Usage: hmac-file-server [options]")
        os.Exit(0)
    }

    if showVersion {
        fmt.Println("hmac-file-server version", versionString)
        os.Exit(0)
    }

    err := readConfig(configFile, &conf)
    if err != nil {
        log.Fatalln("Error reading configuration file:", err)
    }

    setupLogging()

    // Initialize Redis Client if enabled in config
    if conf.RedisEnabled {
        redisClient, err = InitRedisClient()
        if err != nil {
            log.Warnf("Redis not reachable: %v. Falling back to in-memory cache.", err)
            redisClient = nil
        } else {
            checkRedisConnection() // Log the connection status
        }
    }

    if conf.NumCores == "auto" {
        runtime.GOMAXPROCS(runtime.NumCPU())
        log.Infof("Using all available cores: %d", runtime.NumCPU())
    } else {
        numCores, err := strconv.Atoi(conf.NumCores)
        if err != nil || numCores < 1 {
            log.Warn("Invalid NumCores value. Defaulting to 1 core.")
            numCores = 1
        }
        runtime.GOMAXPROCS(numCores)
        log.Infof("Using %d cores", numCores)
    }

    if conf.UnixSocket {
        proto = "unix"
    } else {
        proto = "tcp"
    }

    address := conf.ListenPort
    listener, err := net.Listen(proto, address)
    if err != nil {
        log.Fatalln("Could not open listener:", err)
    }

<<<<<<< HEAD
	// Use the ReadTimeout and WriteTimeout from the config, and enable Keep-Alive
	srv := &http.Server{
		Addr:              address,
		ReadTimeout:       time.Duration(conf.ReadTimeout) * time.Second,
		WriteTimeout:      time.Duration(conf.WriteTimeout) * time.Second,
		IdleTimeout:       120 * time.Second, // Idle timeout for keep-alive
		ReadHeaderTimeout: 60 * time.Second,  // Time to read headers, for keep-alive
		MaxHeaderBytes:    1 << 20,           // 1 MB max header size
		ConnState: func(conn net.Conn, state http.ConnState) {
			log.Infof("Connection state changed: %v", state)
		},
	}
=======
    // Use the ReadTimeout and WriteTimeout from the config, and enable Keep-Alive
    srv := &http.Server{
        Addr:              address,
        ReadTimeout:       time.Duration(conf.ReadTimeout) * time.Second,
        WriteTimeout:      time.Duration(conf.WriteTimeout) * time.Second,
        IdleTimeout:       120 * time.Second, // Idle timeout for keep-alive
        ReadHeaderTimeout: 60 * time.Second,  // Time to read headers, for keep-alive
        MaxHeaderBytes:    1 << 20,           // 1 MB max header size
    }
>>>>>>> origin/main

    // Start metrics server if enabled
    if conf.MetricsEnabled {
        go func() {
            http.Handle("/metrics", promhttp.Handler())
            log.Printf("Metrics server listening on %s", conf.MetricsPort)
            if err := http.ListenAndServe(conf.MetricsPort, nil); err != nil {
                log.Fatalf("Metrics server failed: %v", err)
            }
        }()
    }

    // Start the main server
    go func() {
        http.HandleFunc("/", handleRequest)
        log.Printf("Server started on %s. Waiting for requests.\n", address)
        if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
            log.Fatalf("Server error: %s\n", err)
        }
    }()

    if conf.RetentionPolicyEnabled {
        go func() {
            for {
                if err := deleteOldFiles(); err != nil {
                    log.Errorf("Error deleting old files: %v", err)
                }
                time.Sleep(24 * time.Hour)
            }
        }()
    }

    // Graceful shutdown handling
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
}
