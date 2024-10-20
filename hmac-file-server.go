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
	"github.com/patrickmn/go-cache"
)

// Configuration of this server
type Config struct {
	ListenPort             string
	UnixSocket             bool
	UnixSocketPath         string
	Secret                 string
	StoreDir               string
	UploadSubDir           string
	LogLevel               string
	LogFile                string
	MaxRetries             int
	RetryDelay             int
	EnableGetRetries       bool
	BlockAfterFails        int
	BlockDuration          int
	AutoUnban              bool
	AutoBanTime            int
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
	RedisAddr              string // Redis server address (e.g., "localhost:6379")
	RedisPassword          string // Redis password
	RedisDB                int    // Redis database number
	ReadTimeout            int    `toml:"read_timeout"`   // Read timeout in seconds
	WriteTimeout           int    `toml:"write_timeout"`  // Write timeout in seconds
	BufferSize             int    `toml:"buffer_size"`    // Buffer size for reading file chunks
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
	ReadTimeout:            900,         // Default 900 seconds (15 minutes)
	WriteTimeout:           900,         // Default 900 seconds (15 minutes)
	BufferSize:             65536,       // Default 64 KB buffer size
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

// Initialize Redis Client
func InitRedisClient() *redis.Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:     conf.RedisAddr,      // Redis server address
		Password: conf.RedisPassword,  // Redis password, leave empty for no password
		DB:       conf.RedisDB,        // Redis database number
	})
	return rdb
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

// Reads the configuration file
func readConfig(configFile string, config *Config) error {
	_, err := toml.DecodeFile(configFile, config)
	return err
}

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
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "7200")
}

// Request handler with enhanced error handling, logging, and file streaming
func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Add CORS headers for all responses
	addCORSheaders(w)

	// Handle OPTIONS request for CORS preflight
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method == http.MethodPut {
		startTime := time.Now()

		// Create the directory if it does not exist
		dirPath := path.Join(conf.StoreDir, r.URL.Path)
		if err := EnsureDirectoryExists(path.Dir(dirPath)); err != nil {
			log.Errorf("Failed to ensure directory exists: %s, error: %v", path.Dir(dirPath), err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Open a file to write to
		outFile, err := os.Create(dirPath)
		if err != nil {
			log.Errorf("Error creating file: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer outFile.Close()

		// Create a buffer and read the request body in chunks
		buffer := make([]byte, conf.BufferSize) // Buffer size from config
		var totalBytes int64
		for {
			n, err := r.Body.Read(buffer)
			if err != nil && err != io.EOF {
				log.Errorf("Error reading body: %v", err)
				http.Error(w, "Error reading file", http.StatusInternalServerError)
				uploadErrorsTotal.Inc()
				return
			}

			if n == 0 {
				break
			}

			// Write the chunk to the file
			if _, err := outFile.Write(buffer[:n]); err != nil {
				log.Errorf("Error writing to file: %v", err)
				http.Error(w, "Error writing file", http.StatusInternalServerError)
				uploadErrorsTotal.Inc()
				return
			}
			totalBytes += int64(n)
		}

		// Log successful upload and upload size
		log.Infof("File successfully uploaded: %s, size: %d bytes", dirPath, totalBytes)
		
		// Record upload duration and increment successful uploads count
		duration := time.Since(startTime).Seconds()
		uploadDuration.Observe(duration)
		uploadsTotal.Inc()

		// Return 201 Created as expected by XMPP clients
		w.WriteHeader(http.StatusCreated)
		return
	}

	// Handle file serving (GET method)
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		filePath := path.Join(conf.StoreDir, r.URL.Path)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			log.Warnf("File not found: %s", filePath)
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		log.Infof("Serving file: %s", filePath)
		http.ServeFile(w, r, filePath)
		return
	}

	// Return error for unsupported methods
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

// Main function with graceful shutdown, request timeout, and metrics
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

	// Initialize Redis Client
	redisClient = InitRedisClient()

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

	// Use the ReadTimeout and WriteTimeout from the config, and enable Keep-Alive
	srv := &http.Server{
		Addr:              address,
		ReadTimeout:       time.Duration(conf.ReadTimeout) * time.Second,
		WriteTimeout:      time.Duration(conf.WriteTimeout) * time.Second,
		IdleTimeout:       120 * time.Second,       // Idle timeout for keep-alive
		ReadHeaderTimeout: 60 * time.Second,        // Time to read headers, for keep-alive
		MaxHeaderBytes:    1 << 20,                 // 1 MB max header size
	}

	go func() {
		log.Println("Starting hmac-file-server", versionString, "...")
		if conf.MetricsEnabled {
			http.Handle("/metrics", promhttp.Handler())
			go func() {
				log.Println("Starting metrics server on port", conf.MetricsPort)
				if err := http.ListenAndServe(conf.MetricsPort, nil); err != nil {
					log.Fatalf("Metrics server failed: %s\n", err)
				}
			}()
		}

		subpath := path.Join("/", conf.UploadSubDir)
		subpath = strings.TrimRight(subpath, "/") + "/"
		http.HandleFunc(subpath, handleRequest)
		log.Printf("Server started on %s. Waiting for requests.\n", address)

		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %s\n", err)
		}
	}()

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
