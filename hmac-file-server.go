package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	"sort"
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
	ChecksumVerification   bool
	RetentionPolicyEnabled bool
	MaxRetentionSize       int64
	MaxRetentionTime       string
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
}

var versionString string = "1.0.4"
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

// Calculate checksum of a file using SHA-256
func calculateChecksum(file *os.File) (string, error) {
	hash := sha256.New()
	_, err := io.Copy(hash, file)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
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

		// Write file data to disk
		if _, err := io.Copy(file, r.Body); err != nil {
			log.Errorf("Error copying body to file: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			uploadErrorsTotal.Inc()
			return
		}

		// Checksum verification (optional)
		if conf.ChecksumVerification {
			expectedChecksum := r.Header.Get("X-Checksum")
			if expectedChecksum != "" {
				// Re-open file to calculate checksum
				file.Seek(0, 0)
				actualChecksum, err := calculateChecksum(file)
				if err != nil {
					log.Errorf("Error calculating checksum: %v", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
				if actualChecksum != expectedChecksum {
					log.Errorf("Checksum mismatch for file %s: expected %s, got %s", filePath, expectedChecksum, actualChecksum)
					http.Error(w, "Checksum Mismatch", http.StatusBadRequest)
					return
				}
			} else {
				log.Warnf("No checksum provided for file %s. Skipping checksum validation.", filePath)
			}
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

// Function to get total storage size of the files
func getTotalStorageSize(dir string) (int64, error) {
	var size int64
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

// Struct to hold file information for sorting
type FileInfo struct {
	Path string
	Info os.FileInfo
}

// Function to get files sorted by modification time (oldest first)
func getFilesSortedByAge(dir string) ([]FileInfo, error) {
	var files []FileInfo
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, FileInfo{Path: path, Info: info})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Sort files by modification time (oldest first)
	sort.Slice(files, func(i, j int) bool {
		return files[i].Info.ModTime().Before(files[j].Info.ModTime())
	})
	return files, nil
}

// Function to delete oldest files until the size is under the limit
func deleteOldestFiles(dir string, excessSize int64) {
	files, err := getFilesSortedByAge(dir)
	if err != nil {
		log.Errorf("Error getting files by age: %v", err)
		return
	}
	var deletedSize int64
	for _, file := range files {
		if deletedSize >= excessSize {
			break
		}
		fileSize := file.Info.Size()
		os.Remove(file.Path)
		deletedSize += fileSize
		log.Infof("Deleted file: %s (Size: %d bytes)", file.Path, fileSize)
	}
}

// Function to delete files older than a specific duration
func deleteFilesOlderThan(dir string, maxAge string) {
	var cutoff time.Time

	// Check for year (y) or day (d) units and handle them manually
	if strings.HasSuffix(maxAge, "y") {
		years, err := strconv.Atoi(strings.TrimSuffix(maxAge, "y"))
		if err != nil {
			log.Errorf("Invalid maxAge format: %v", err)
			return
		}
		cutoff = time.Now().AddDate(-years, 0, 0)  // Subtract years from the current time
	} else if strings.HasSuffix(maxAge, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(maxAge, "d"))
		if err != nil {
			log.Errorf("Invalid maxAge format: %v", err)
			return
		}
		cutoff = time.Now().AddDate(0, 0, -days)  // Subtract days from the current time
	} else {
		// Handle regular durations like "h", "m", "s"
		duration, err := time.ParseDuration(maxAge)
		if err != nil {
			log.Errorf("Invalid maxAge format: %v", err)
			return
		}
		cutoff = time.Now().Add(-duration)
	}

	log.Infof("Deleting files older than: %s (cutoff: %s)", maxAge, cutoff.Format(time.RFC3339))

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			log.Infof("Checking file: %s (modified: %s)", path, info.ModTime().Format(time.RFC3339))

			// Only delete files older than the specified age
			if info.ModTime().Before(cutoff) {
				log.Infof("Deleting file due to age: %s", path)
				os.Remove(path)
			}
		}
		return nil
	})
	if err != nil {
		log.Errorf("Error deleting old files: %v", err)
	}
}

// Enforce retention policy based on size and age
func enforceRetentionPolicy() {
	if !conf.RetentionPolicyEnabled {
		return
	}

	// Check total size of the storage directory
	totalSize, err := getTotalStorageSize(conf.StoreDir)
	if err != nil {
		log.Errorf("Error calculating total storage size: %v", err)
		return
	}

	// If size exceeds the maximum allowed, delete the oldest files
	if totalSize > conf.MaxRetentionSize {
		log.Infof("Total storage size exceeds limit: %d bytes. Starting cleanup...", totalSize)
		deleteOldestFiles(conf.StoreDir, totalSize-conf.MaxRetentionSize)
	}

	// Delete files older than MaxRetentionTime
	deleteFilesOlderThan(conf.StoreDir, conf.MaxRetentionTime)
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

	// Launch retention policy checks in a separate goroutine
	go func() {
		for {
			enforceRetentionPolicy()
			time.Sleep(24 * time.Hour) // Run retention checks daily
		}
	}()

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
