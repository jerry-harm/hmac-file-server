package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"crypto/tls"
	"os/signal"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"
)

/*
 * Configuration of this server
 */
type Config struct {
	ListenPort             string
	UnixSocket             bool
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
	DeleteFilesReport      bool
	DeleteFilesReportPath  string
}

var conf = Config{
	ListenPort: "8080", 
	MaxRetries: 3,      
	RetryDelay: 5,     
}

var versionString string = "c97fa66"
var log = &logrus.Logger{
	Out:       os.Stdout,
	Formatter: new(logrus.TextFormatter),
	Hooks:     make(logrus.LevelHooks),
	Level:     logrus.DebugLevel,
}

// Minimum free space threshold (100MB in this case, adjustable)
const minFreeSpaceThreshold int64 = 100 * 1024 * 1024

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

/*
 * Rate limiting and banning structures
 */
type RateLimit struct {
	failedAttempts int
	blockExpires   time.Time
	banned         bool
}

var rateLimits sync.Map
var rateLimitMutex sync.Mutex

/*
 * Prints the help message with descriptions of available flags and options
 */
func printHelp() {
	helpText := `
Usage: hmac-file-server [options]

Options:
  -config string
        Path to the configuration file "config.toml" (default is "./config.toml")
  -help
        Display this help message and exit
  -version
        Show the version of the program and exit

Description:
  hmac-file-server is a file handling server for uploading and downloading files, designed with security in mind.
  It verifies HMAC signatures to ensure secure file transfers, provides retry mechanisms for file access, and
  has configurable options to control server behavior such as logging levels, retry delays, and maximum retry attempts.

Example:
  ./hmac-file-server --config=config.toml
`
	fmt.Println(helpText)
}

/*
 * Sets CORS headers for all responses
 */
func addCORSheaders(w http.ResponseWriter) {
	// Set common CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*") 
	w.Header().Set("Access-Control-Allow-Methods", ALLOWED_METHODS)
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
	w.Header().Set("Access-Control-Allow-Credentials", "true") 
	w.Header().Set("Access-Control-Max-Age", "7200")
}

/*
 * Check if a path is rate-limited or banned
 */
func isRateLimitedOrBanned(path string) bool {
	// Fetch rate limit struct using sync.Map
	if value, exists := rateLimits.Load(path); exists {
		rateLimit := value.(*RateLimit)
		if rateLimit.banned {
			// Check if the auto-ban time has expired and unban if necessary
			if conf.AutoUnban && time.Now().After(rateLimit.blockExpires) {
				rateLimit.banned = false
				rateLimit.failedAttempts = 0
				log.Infof("Auto-unbanned path: %s", path)
				return false
			}
			return true // Still banned
		}
		if time.Now().Before(rateLimit.blockExpires) {
			return true // Blocked
		}
		// Reset if the block has expired
		rateLimit.failedAttempts = 0
	}
	return false
}

/*
 * Update failed attempts and potentially ban or block the path
 */
func updateFailedAttempts(path string) {
	// Fetch or create RateLimit entry using sync.Map
	value, _ := rateLimits.LoadOrStore(path, &RateLimit{})
	rateLimit := value.(*RateLimit)

	rateLimit.failedAttempts++

	if rateLimit.failedAttempts >= conf.BlockAfterFails {
		// Ban the path for the configured ban time
		rateLimit.blockExpires = time.Now().Add(time.Duration(conf.AutoBanTime) * time.Second)
		rateLimit.banned = true
		log.Warnf("Banning path %s for %d seconds due to too many failed attempts", path, conf.AutoBanTime)
	}
}

/*
 * Request handler
 */
func handleRequest(w http.ResponseWriter, r *http.Request) {
	if r == nil {
		log.Error("Received nil request")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	addCORSheaders(w)

	if r.Method == http.MethodOptions {
		// Handle CORS preflight request
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.URL == nil {
		log.Error("Request URL is nil")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if isRateLimitedOrBanned(r.URL.Path) {
		log.Warn("Request blocked due to rate limiting or ban: ", r.URL.Path)
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	if conf.StoreDir == "" {
		log.Error("StoreDir is not set in the configuration")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if conf.Secret == "" {
		log.Error("Secret is not set in the configuration")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if conf.UploadSubDir == "" {
		log.Error("UploadSubDir is not set in the configuration")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if conf.MaxRetries <= 0 || conf.RetryDelay <= 0 {
		log.Error("Invalid configuration for MaxRetries or RetryDelay")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if conf.LogLevel == "debug" {
		log.Info("Incoming request with full details: ", r.Method, r.URL.String())
	} else {
		log.Info("Incoming request: ", r.Method)
	}

	// Handle file upload
	if r.Method == http.MethodPut {
		// Check for available space
		if err := hasEnoughSpace(conf.StoreDir, r.ContentLength); err != nil {
			log.Warn(err.Error())
			http.Error(w, err.Error(), http.StatusInsufficientStorage)
			return
		}
		// Handle MAC validation and file creation...
		//...
	}
}

/*
 * File Deletion Logic
 */
func deleteOldFiles() {
	if !conf.DeleteFiles {
		return
	}

	duration, err := parsePeriod(conf.DeleteFilesAfterPeriod)
	if err != nil {
		log.Fatalf("Invalid delete_files_after_period format: %v", err)
	}

	uploadDir := filepath.Join(conf.StoreDir, conf.UploadSubDir)

	// Traverse and delete old files
	err = filepath.Walk(uploadDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if time.Since(info.ModTime()) > duration {
			if conf.DeleteFilesReport {
				writeDeleteReport(path)
			}
			log.Printf("Deleting file: %s", path)
			return os.RemoveAll(path)
		}
		return nil
	})

	if err != nil {
		log.Fatalf("Error while deleting files: %v", err)
	}
}

// Parse period like "30d", "2m", "1y" to a time.Duration
func parsePeriod(period string) (time.Duration, error) {
	unit := period[len(period)-1]
	amount, err := strconv.Atoi(period[:len(period)-1])
	if err != nil {
		return 0, fmt.Errorf("invalid period format")
	}

	switch unit {
	case 'd':
		return time.Duration(amount) * 24 * time.Hour, nil
	case 'm':
		return time.Duration(amount) * 30 * 24 * time.Hour, nil 
	case 'y':
		return time.Duration(amount) * 365 * 24 * time.Hour, nil 
	default:
		return 0, fmt.Errorf("invalid time unit: %v", unit)
	}
}

// Write deleted files to a report
func writeDeleteReport(filePath string) {
	reportPath := conf.DeleteFilesReportPath
	if reportPath == "" {
		reportPath = "./deleted_files.log"
	}

	f, err := os.OpenFile(reportPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open report file: %v", err)
	}
	defer f.Close()

	if _, err := f.WriteString(fmt.Sprintf("%s - Deleted file: %s\n", time.Now().Format(time.RFC3339), filePath)); err != nil {
		log.Fatalf("Failed to write to report: %v", err)
	}
}

// Schedule file deletion task to run daily
func scheduleFileDeletion() {
	go func() {
		for {
			deleteOldFiles()
			time.Sleep(24 * time.Hour) 
		}
	}()
}

/*
 * Main function
 */
func main() {
	var configFile string
	var showHelp bool
	var showVersion bool
	var proto string

	/*
	 * Define and parse startup arguments
	 */
	flag.StringVar(&configFile, "config", "./config.toml", "Path to configuration file \"config.toml\".")
	flag.BoolVar(&showHelp, "help", false, "Display this help message")
	flag.BoolVar(&showVersion, "version", false, "Show the version of the program")

	flag.Parse()

	if showHelp {
		printHelp()
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

	if conf.UnixSocket {
		proto = "unix"
	} else {
		proto = "tcp"
	}

	srv := &http.Server{
		Addr: conf.ListenPort,
		TLSConfig: &tls.Config{
			NextProtos: []string{"h2", "http/1.1"}, 
		},
	}

	// Start file deletion scheduler
	scheduleFileDeletion()

	// Start HTTP server in a separate goroutine
	go func() {
		log.Println("Starting hmac-file-server", versionString, "...")
		listener, err := net.Listen(proto, conf.ListenPort)
		if err != nil {
			log.Fatalln("Could not open listening socket:", err)
		}

		subpath := path.Join("/", conf.UploadSubDir)
		subpath = strings.TrimRight(subpath, "/")
		subpath += "/"
		http.HandleFunc(subpath, handleRequest)
		log.Printf("Server started on port %s. Waiting for requests.\n", conf.ListenPort)

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
