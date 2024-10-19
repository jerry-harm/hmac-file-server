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
}

var conf = Config{
	ListenPort:             ":8080",
	MaxRetries:             5,
	RetryDelay:             2,
	ReaskSecretEnabled:     true,
	ReaskSecretInterval:    "24h",
	MetricsEnabled:         true,
	MetricsPort:            ":9090",
}

var versionString string = "1.0.3-final"
var log = logrus.New()

// Initialize an in-memory cache with default expiration and cleanup interval.
var fileMetadataCache = cache.New(5*time.Minute, 10*time.Minute)

// Rate limiting and banning structures
type RateLimit struct {
	failedAttempts int
	blockExpires   time.Time
	banned         bool
}

var rateLimits sync.Map

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

// Allowed HTTP methods
var ALLOWED_METHODS = strings.Join([]string{
	http.MethodOptions,
	http.MethodHead,
	http.MethodGet,
	http.MethodPut,
}, ", ")

// Reads the configuration file
func readConfig(configFile string, config *Config) error {
	_, err := toml.DecodeFile(configFile, config)
	return err
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

// WriteFile writes the given data to the specified file path.
func writeFile(filePath string, data []byte) error {
	file, err := os.Create(filePath)
	if err != nil {
		log.Errorf("Error creating file: %s, error: %v", filePath, err)
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		log.Errorf("Error writing to file: %s, error: %v", filePath, err)
		return err
	}
	log.Infof("Successfully wrote file: %s", filePath)
	return nil
}

// Request handler with enhanced error handling, logging, and file streaming
func handleRequest(w http.ResponseWriter, r *http.Request) {
	if r == nil {
		log.Error("Received nil request")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.WithFields(logrus.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
		"ip":     r.RemoteAddr,
	}).Info("Handling request")

	addCORSheaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	dirPath := path.Join(conf.StoreDir, r.URL.Path)
	filePath := dirPath

	if err := EnsureDirectoryExists(path.Dir(filePath)); err != nil {
		log.Errorf("Failed to ensure directory exists: %s, error: %v", path.Dir(filePath), err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodPut {
		startTime := time.Now()

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

		duration := time.Since(startTime).Seconds()
		uploadDuration.Observe(duration)
		uploadsTotal.Inc()

		w.WriteHeader(http.StatusCreated)
		log.Infof("File successfully uploaded: %s", filePath)
		return
	}

	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			log.Warnf("File not found: %s", filePath)
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		log.Infof("Serving file: %s", filePath)
		http.ServeFile(w, r, filePath)
		return
	}

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

// CORS headers function
func addCORSheaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", ALLOWED_METHODS)
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "7200")
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

	srv := &http.Server{
		Addr:         address,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
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
