package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
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
	NumCores               string // Number of CPU cores to use ("auto" or a number)
	ReaskSecretEnabled     bool   `toml:"reask_secret_enabled"`
	ReaskSecretInterval    string `toml:"reask_secret_interval"`
	MetricsEnabled         bool   `toml:"metrics_enabled"`
	MetricsPort            string `toml:"metrics_port"`
	MinFreeSpaceThreshold  int64  // Minimum free space threshold in bytes
	MaxUploadSize          int64
	BufferSize             int64
}

var conf = Config{
	ListenPort:             ":8080",
	MaxRetries:             5,
	RetryDelay:             2,
	ReaskSecretEnabled:     true,
	ReaskSecretInterval:    "24h", // Default interval for reasking secret
	MetricsEnabled:         true,
	MetricsPort:            ":9090", // Default metrics port
	MinFreeSpaceThreshold:  100 * 1024 * 1024, // Default 100MB threshold
	MaxUploadSize:          1073741824,        // 1 GB default
	BufferSize:             65536,             // 64KB default
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

// Function to prompt for user input
func promptUser(prompt string, defaultValue string) string {
	fmt.Printf("%s [%s]: ", prompt, defaultValue)
	var input string
	_, err := fmt.Scanln(&input)
	if err != nil || input == "" {
		return defaultValue
	}
	return input
}

// Function to create config.toml interactively
func createConfigInteractively(configFile string) {
	fmt.Println("Config file not found. Entering interactive setup mode...")

	conf.ListenPort = promptUser("Enter the server listen port", conf.ListenPort)
	conf.UnixSocket = promptUser("Use Unix Socket (true/false)", "false") == "true"
	if conf.UnixSocket {
		conf.UnixSocketPath = promptUser("Enter the Unix Socket Path", "/home/hmac-file-server/hmac.sock")
	}
	conf.Secret = promptUser("Enter the secret key for HMAC authentication", "your-hmac-secret-key")
	conf.StoreDir = promptUser("Enter the directory for storing files", "/mnt/storage/hmac-file-server/")
	conf.UploadSubDir = promptUser("Enter the upload subdirectory", "upload")
	conf.LogLevel = promptUser("Enter the logging level (debug/info/warn/error)", "info")
	conf.LogFile = promptUser("Enter the log file path (leave empty for console logging)", "")
	conf.MaxUploadSize, _ = strconv.ParseInt(promptUser("Enter max upload size (bytes)", "1073741824"), 10, 64)
	conf.BufferSize, _ = strconv.ParseInt(promptUser("Enter buffer size (bytes)", "65536"), 10, 64)
	conf.MinFreeSpaceThreshold, _ = strconv.ParseInt(promptUser("Enter minimum free space threshold (bytes)", "104857600"), 10, 64)
	conf.MetricsEnabled = promptUser("Enable Prometheus metrics (true/false)", "true") == "true"
	conf.MetricsPort = promptUser("Enter the Prometheus metrics port", ":9090")

	// Write to config.toml
	file, err := os.Create(configFile)
	if err != nil {
		log.Fatalf("Error creating config file: %v", err)
	}
	defer file.Close()

	encoder := toml.NewEncoder(file)
	err = encoder.Encode(conf)
	if err != nil {
		log.Fatalf("Error writing to config file: %v", err)
	}

	fmt.Printf("Configuration saved to %s. Starting the server...\n", configFile)
}

// Reads the configuration file
func readConfig(configFile string, config *Config) error {
	_, err := toml.DecodeFile(configFile, config)
	return err
}

// Main function
func main() {
	var configFile string
	var showHelp bool
	var showVersion bool

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

	// Check if config file exists, otherwise enter interactive mode
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		createConfigInteractively(configFile)
	} else {
		err := readConfig(configFile, &conf)
		if err != nil {
			log.Fatalf("There was an error while reading the configuration file: %v", err)
		}
	}

	// Continue with starting the server...
	fmt.Println("Server is starting...")
}
