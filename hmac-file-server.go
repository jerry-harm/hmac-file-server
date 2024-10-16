package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"flag"
	"fmt"
	"io/ioutil"
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

	"github.com/sirupsen/logrus"
	"github.com/patrickmn/go-cache"
	"github.com/BurntSushi/toml"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	NumCores               string // Number of CPU cores to use ("auto" or a number)
	ReaskSecretEnabled     bool   `toml:"reask_secret_enabled"`
	ReaskSecretInterval    string `toml:"reask_secret_interval"`
	MetricsEnabled         bool   `toml:"metrics_enabled"`
	MetricsPort            string `toml:"metrics_port"`
}

var conf = Config{
	ListenPort:             ":8080",
	MaxRetries:             5,
	RetryDelay:             2,
	ReaskSecretEnabled:     true,
	ReaskSecretInterval:    "24h", // Default interval for reasking secret
	MetricsEnabled:         true,
	MetricsPort:            ":9090", // Default metrics port
}

var versionString string = "c97fa66"
var log = &logrus.Logger{
	Out:       os.Stdout,
	Formatter: new(logrus.TextFormatter),
	Hooks:     make(logrus.LevelHooks),
	Level:     logrus.DebugLevel,
}

// Initialize an in-memory cache with default expiration and cleanup interval.
var fileMetadataCache = cache.New(5*time.Minute, 10*time.Minute)

// Minimum free space threshold as a variable (100MB in this case, adjustable)
var minFreeSpaceThreshold int64 = 100 * 1024 * 1024 // 100MB

// Allowed HTTP methods
var ALLOWED_METHODS string = strings.Join(
	[]string{
		http.MethodOptions,
		http.MethodHead,
		http.MethodGet,
		http.MethodPut,
	},
	", ",
)

// Rate limiting and banning structures
type RateLimit struct {
	failedAttempts int
	blockExpires   time.Time
	banned         bool
}

var rateLimits sync.Map
var rateLimitMutex sync.Mutex

// Pool for reusable HMAC instances
var hmacPool = sync.Pool{
	New: func() interface{} {
		return hmac.New(sha256.New, []byte(conf.Secret))
	},
}

// Prometheus metrics
var (
	goroutines = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "hmac_file_server_goroutines",
		Help: "Number of goroutines that currently exist.",
	})

	totalUploads = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hmac_file_server_total_uploads",
			Help: "Total number of uploads",
		},
		[]string{"status"},
	)

	totalDownloads = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hmac_file_server_total_downloads",
			Help: "Total number of downloads",
		},
		[]string{"status"},
	)

	uploadDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "hmac_file_server_upload_duration_seconds",
			Help:    "Duration of uploads in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)
)

func init() {
	// Register metrics
	prometheus.MustRegister(goroutines)
	prometheus.MustRegister(totalUploads)
	prometheus.MustRegister(totalDownloads)
	prometheus.MustRegister(uploadDuration)
}

// Reads the configuration file
func readConfig(configFile string, config *Config) error {
	_, err := toml.DecodeFile(configFile, config)
	return err
}

// Sets the log level
func setLogLevel() {
	level, err := logrus.ParseLevel(conf.LogLevel)
	if err != nil {
		logrus.Warnf("Invalid log level: %s. Defaulting to 'info'.", conf.LogLevel)
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

// WriteFileResumable writes data to the specified file, supporting resume by seeking to a byte offset.
func WriteFileResumable(filePath string, data []byte, offset int64) error {
	// Open the file for writing, creating it if necessary, and support appending
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Errorf("Error opening file for writing: %s, error: %v", filePath, err)
		return err
	}
	defer file.Close()

	// Seek to the desired offset
	if offset > 0 {
		_, err = file.Seek(offset, 0) // Seek from the beginning of the file
		if err != nil {
			log.Errorf("Error seeking to offset %d: %v", offset, err)
			return err
		}
	}

	// Write the data starting at the specified offset
	_, err = file.Write(data)
	if err != nil {
		log.Errorf("Error writing to file: %s, error: %v", filePath, err)
		return err
	}

	log.Infof("Successfully wrote data to file: %s starting from offset %d", filePath, offset)
	return nil
}

// Request handler with detailed logging
func handleRequest(w http.ResponseWriter, r *http.Request) {
	if r == nil {
		log.Error("Received nil request")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Log the incoming request method and URL path for debugging
	log.Infof("Handling %s request for path: %s", r.Method, r.URL.Path)

	// Update the goroutine metric
	goroutines.Set(float64(runtime.NumGoroutine()))

	addCORSheaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.URL == nil {
		log.Error("Request URL is nil")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Define the path where the file will be stored
	dirPath := path.Join(conf.StoreDir, r.URL.Path)
	filePath := dirPath // Update with your desired file name logic

	// Ensure the directory exists before handling the file
	if err := EnsureDirectoryExists(path.Dir(filePath)); err != nil {
		log.Errorf("Failed to ensure directory exists: %s, error: %v", path.Dir(filePath), err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Handle PUT request (upload file)
	if r.Method == http.MethodPut {
		// Check if the request contains a Range header to resume an upload
		rangeHeader := r.Header.Get("Range")
		var offset int64 = 0
		var err error // Define err here

		if rangeHeader != "" {
			// Example: "Range: bytes=1024-"
			rangeParts := strings.Split(rangeHeader, "=")
			if len(rangeParts) == 2 && strings.HasPrefix(rangeParts[1], "bytes") {
				offsetStr := strings.TrimPrefix(rangeParts[1], "bytes=")
				offset, err = strconv.ParseInt(offsetStr, 10, 64)
				if err != nil {
					log.Errorf("Invalid Range header: %s", rangeHeader)
					http.Error(w, "Invalid Range header", http.StatusBadRequest)
					return
				}
			}
		}

		// Read the body data
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Errorf("Error reading body: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Log the upload progress
		log.Infof("Received %d bytes of data for path: %s with offset %d", len(body), filePath, offset)

		// Write the file with the ability to resume from the specified offset
		if err := WriteFileResumable(filePath, body, offset); err != nil {
			log.Errorf("Failed to write file: %s, error: %v", filePath, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Update metrics after successful upload
		totalUploads.WithLabelValues("success").Inc()

		// Set the status code
		w.WriteHeader(http.StatusCreated)
		log.Infof("File successfully uploaded/resumed: %s", filePath)
		return
	}

	// Handle GET or HEAD request (serve file)
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		// Explicitly check if the file exists before serving
		fileInfo, err := os.Stat(filePath)
		if os.IsNotExist(err) {
			log.Warnf("File not found: %s", filePath)
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}

		if err != nil {
			log.Errorf("Error accessing file: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if fileInfo.IsDir() {
			http.Error(w, "Directory listing forbidden", http.StatusForbidden)
			return
		}

		// Serve the file
		log.Infof("Serving file: %s", filePath)
		http.ServeFile(w, r, filePath) // Automatically handles headers

		// Update metrics after successful download
		totalDownloads.WithLabelValues("success").Inc()
		return
	}

	// If the method is not allowed, send a 405 Method Not Allowed
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

// Main function
func main() {
	var configFile string
	var showHelp bool
	var showVersion bool
	var proto string

	// Define and parse startup arguments
	flag.StringVar(&configFile, "config", "./config.toml", "Path to configuration file \"config.toml\".")
	flag.BoolVar(&showHelp, "help", false, "Display this help message")
	flag.BoolVar(&showVersion, "version", false, "Show the version of the program")

	flag.Parse()

	if showHelp {
		fmt.Println(`
Usage: hmac-file-server [options]

Options:
  -config string
        Path to the configuration file "config.toml" (default is "./config.toml")
  -help
        Display this help message and exit
  -version
        Show the version of the program and exit
        `)
		os.Exit(0)
	}

	if showVersion {
		fmt.Println("hmac-file-server version", versionString)
		os.Exit(0)
	}

	// Read config file
	err := readConfig(configFile, &conf)
	if err != nil {
		log.Fatalln("There was an error while reading the configuration file:", err)
	}

	// Set the number of cores based on config
	if conf.NumCores == "auto" {
		runtime.GOMAXPROCS(runtime.NumCPU()) // Use all available cores
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

	// Determine protocol and address based on UnixSocket flag
	var address string
	if conf.UnixSocket {
		proto = "unix"
		address = conf.UnixSocketPath
		log.Infof("Using Unix socket at: %s", address)
	} else {
		proto = "tcp"
		address = conf.ListenPort
		log.Infof("Using TCP socket at: %s", address)
	}

	// Create listener based on the protocol
	listener, err := net.Listen(proto, address)
	if err != nil {
		log.Fatalln("Could not open listener:", err)
	}

	srv := &http.Server{
		Addr: address,
	}

	// Start HTTP server in a separate goroutine
	go func() {
		log.Println("Starting hmac-file-server", versionString, "...")

		// Handle the metrics endpoint if enabled
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
		subpath = strings.TrimRight(subpath, "/")
		subpath += "/"
		http.HandleFunc(subpath, handleRequest) // Directly handle requests

		log.Printf("Server started on %s. Waiting for requests.\n", address)

		setLogLevel()

		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	if err := srv.Shutdown(nil); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}
}
