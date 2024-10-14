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
	ListenPort       string
	UnixSocket       bool
	Secret           string
	StoreDir         string
	UploadSubDir     string
	LogLevel         string
	MaxRetries       int    // Retry attempts if file is not found
	RetryDelay       int    // Delay between retries in seconds
	EnableGetRetries bool   // Enable retries for GET requests
	BlockAfterFails  int    // Number of failed attempts before blocking
	BlockDuration    int    // Duration to block in seconds after too many fails
	AutoUnban        bool   // Auto unban after time period
	AutoBanTime      int    // Time in seconds for how long to ban before unban
}

var conf = Config{
	ListenPort: "8080", // Default port
	MaxRetries: 3,      // Default retries
	RetryDelay: 5,      // Default retry delay in seconds
}

var versionString string = "c97fa66"
var log = &logrus.Logger{
	Out:       os.Stdout,
	Formatter: new(logrus.TextFormatter),
	Hooks:     make(logrus.LevelHooks),
	Level:     logrus.DebugLevel,
}

// Minimum free space threshold (100MB in this case, adjustable)
const minFreeSpaceThreshold int64 = 100 * 1024 * 1024 // Default to 100MB

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

// Use sync.Map for concurrent access
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
	w.Header().Set("Access-Control-Allow-Origin", "*") // You can replace '*' with a specific domain if needed
	w.Header().Set("Access-Control-Allow-Methods", ALLOWED_METHODS)
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
	w.Header().Set("Access-Control-Allow-Credentials", "true")  // Set to true if you expect credentials (cookies, tokens, etc.)
	w.Header().Set("Access-Control-Max-Age", "7200")
}

/*
 * Check if there is enough free space on the filesystem where StoreDir is located.
 */
// func hasEnoughSpace(path string, fileSize int64) error {
//	var stat syscall.Statfs_t
//	// Get filesystem stats
//	if err := syscall.Statfs(path, &stat); err != nil {
//		return fmt.Errorf("failed to get filesystem stats: %v", err)
//	}

//	// Available blocks * size per block = available bytes
//	freeSpace := stat.Bavail * uint64(stat.Bsize)

//	if int64(freeSpace) < fileSize {
//		return fmt.Errorf("not enough space to upload file")
//	}

//	if int64(freeSpace) < minFreeSpaceThreshold {
//		return fmt.Errorf("disk space is below minimum free space threshold")
//	}

//	return nil
//}

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
 * Handles file upload/download requests and CORS preflight requests
 */
func handleRequest(w http.ResponseWriter, r *http.Request) {
	if r == nil {
		log.Error("Received nil request")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Always apply CORS headers for all requests (including preflight and actual requests)
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

	// Check if the path is rate-limited or banned
	if isRateLimitedOrBanned(r.URL.Path) {
		log.Warn("Request blocked due to rate limiting or ban: ", r.URL.Path)
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// Proceed with handling the request
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

	// Parse URL and args
	p := r.URL.Path
	a, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		log.Warn("Failed to parse query")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	subDir := path.Join("/", conf.UploadSubDir)
	fileStorePath := strings.TrimPrefix(p, subDir)
	if fileStorePath == "" || fileStorePath == "/" {
		log.Warn("Access to the root path (/) is forbidden for security reasons.")
		http.Error(w, "Forbidden: Root path access is not allowed.", http.StatusForbidden)
		return
	} else if fileStorePath[0] == '/' {
		fileStorePath = fileStorePath[1:]
	}

	// Prevent path traversal
	if strings.Contains(fileStorePath, "..") {
		log.Warn("Path traversal attempt detected: ", fileStorePath)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	absFilename := filepath.Join(conf.StoreDir, fileStorePath)

	// File upload handling (PUT)
	if r.Method == http.MethodPut {
		// Check if there's enough space for the file
		if err := hasEnoughSpace(conf.StoreDir, r.ContentLength); err != nil {
			log.Warn(err.Error())
			http.Error(w, err.Error(), http.StatusInsufficientStorage)
			return
		}

		// Check if MAC is attached to URL and verify protocol version
		var protocolVersion string
		if a["v2"] != nil {
			protocolVersion = "v2"
		} else if a["token"] != nil {
			protocolVersion = "token"
		} else if a["v"] != nil {
			protocolVersion = "v"
		} else {
			log.Warn("No HMAC attached to URL. Expecting URL with \"v\", \"v2\" or \"token\" parameter as MAC")
			http.Error(w, "No HMAC attached to URL. Expecting URL with \"v\", \"v2\" or \"token\" parameter as MAC", http.StatusForbidden)
			return
		}

		// Initialize HMAC
		mac := hmac.New(sha256.New, []byte(conf.Secret))
		macString := ""

		// Calculate MAC based on protocolVersion
		if protocolVersion == "v" {
			// Use a space character (0x20) between components of MAC
			mac.Write([]byte(fileStorePath + "\x20" + strconv.FormatInt(r.ContentLength, 10)))
			macString = hex.EncodeToString(mac.Sum(nil))
		} else if protocolVersion == "v2" || protocolVersion == "token" {
			contentType := mime.TypeByExtension(filepath.Ext(fileStorePath))
			if contentType == "" {
				contentType = "application/octet-stream"
			}

			// Use a null byte character (0x00) between components of MAC
			mac.Write([]byte(fileStorePath + "\x00" + strconv.FormatInt(r.ContentLength, 10) + "\x00" + contentType))
			macString = hex.EncodeToString(mac.Sum(nil))
		}

		// Validate MAC
		if hmac.Equal([]byte(macString), []byte(a[protocolVersion][0])) {
			err = createFile(absFilename, fileStorePath, w, r)
			if err != nil {
				log.Error(err)
			}
			return
		} else {
			log.Warn("Invalid MAC.")
			http.Error(w, "Invalid MAC", http.StatusForbidden)
			return
		}
	}

	// Handle file download (GET/HEAD)
	if r.Method == http.MethodHead || r.Method == http.MethodGet {
		var fileInfo os.FileInfo
		var err error

		if conf.EnableGetRetries {
			// Retry logic for file retrieval
			for attempt := 1; attempt <= conf.MaxRetries; attempt++ {
				fileInfo, err = os.Stat(absFilename)
				if err == nil && !fileInfo.IsDir() {
					break // File found
				}

				if attempt < conf.MaxRetries {
					log.Warnf("File not found. Retry attempt %d/%d...", attempt, conf.MaxRetries)
					time.Sleep(time.Duration(conf.RetryDelay) * time.Second)
				} else {
					log.Error("File not found after retries:", absFilename)
					http.Error(w, "File Not Found", http.StatusNotFound)
					return
				}
			}
		} else {
			fileInfo, err = os.Stat(absFilename)
			if err != nil || fileInfo.IsDir() {
				log.Error("File not found or is a directory:", absFilename)
				http.Error(w, "File Not Found", http.StatusNotFound)
				updateFailedAttempts(r.URL.Path) // Log the failed attempt
				return
			}
		}

		// Set content type and send file
		contentType := mime.TypeByExtension(filepath.Ext(fileStorePath))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		w.Header().Set("Content-Type", contentType)

		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))
		} else {
			http.ServeFile(w, r, absFilename)
		}
		return
	}
}

/*
 * Creates the file on disk
 */
func createFile(absFilename string, fileStorePath string, w http.ResponseWriter, r *http.Request) error {
	// Make sure the directory path exists
	absDirectory := filepath.Dir(absFilename)
	err := os.MkdirAll(absDirectory, os.ModePerm)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return fmt.Errorf("failed to create directory %s: %s", absDirectory, err)
	}

	// Make sure the target file exists (MUST NOT exist before! -> O_EXCL)
	targetFile, err := os.OpenFile(absFilename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		if os.IsExist(err) {
			log.Warn("File already exists: ", absFilename)
			http.Error(w, "Conflict", http.StatusConflict)
		} else if os.IsPermission(err) {
			log.Error("Permission denied while creating file: ", absFilename)
			http.Error(w, "Forbidden", http.StatusForbidden)
		} else {
			log.Error("Unexpected error while creating file: ", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return fmt.Errorf("failed to create file %s: %s", absFilename, err)
	}
	defer targetFile.Close()

	// Copy file contents to file
	_, err = io.Copy(targetFile, r.Body)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return fmt.Errorf("failed to copy file contents to %s: %s", absFilename, err)
	}

	w.WriteHeader(http.StatusCreated)
	return nil
}

/*
 * Reads the configuration from a TOML file
 */
func readConfig(configFilename string, conf *Config) error {
	configData, err := os.ReadFile(configFilename)
	if err != nil {
		log.Fatal("Configuration file config.toml cannot be read:", err, "...Exiting.")
		return err
	}

	if _, err := toml.Decode(string(configData), conf); err != nil {
		log.Fatal("Config file config.toml is invalid:", err)
		return err
	}

	return nil
}

/*
 * Sets the log level for the application
 */
func setLogLevel() {
	switch conf.LogLevel {
	case "debug":
		log.SetLevel(logrus.DebugLevel)
	case "info":
		log.SetLevel(logrus.InfoLevel)
	case "warn":
		log.SetLevel(logrus.WarnLevel)
	case "error":
		log.SetLevel(logrus.ErrorLevel)
	default:
		log.SetLevel(logrus.WarnLevel)
		fmt.Print("Invalid log level set in config. Defaulting to \"warn\"")
	}
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

	/*
	 * Handle --help and --version flags
	 */
	if showHelp {
		printHelp()
		os.Exit(0)
	}

	if showVersion {
		fmt.Println("hmac-file-server version", versionString)
		os.Exit(0)
	}

	/*
	 * Read config file
	 */
	err := readConfig(configFile, &conf)
	if err != nil {
		log.Fatalln("There was an error while reading the configuration file:", err)
	}

	// Select proto
	if conf.UnixSocket {
		proto = "unix"
	} else {
		proto = "tcp"
	}

	/*
	 * Graceful shutdown setup
	 */
	srv := &http.Server{
		Addr: conf.ListenPort,
		TLSConfig: &tls.Config{
			NextProtos: []string{"h2", "http/1.1"}, // Support HTTP/2
		},
	}

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

		// Set log level
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
