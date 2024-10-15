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
	ReaskSecretEnabled     bool   `toml:"reask_secret_enabled"`    // Enable reasking for the secret
	ReaskSecretInterval    string `toml:"reask_secret_interval"`   // Interval for reasking the secret
}

var conf = Config{
	ListenPort:             ":8080",
	MaxRetries:             5,
	RetryDelay:             2,
	ReaskSecretEnabled:     true,
	ReaskSecretInterval:    "24h", // Default interval for reasking secret
}

var versionString string = "c97fa66"
var log = &logrus.Logger{
	Out:       os.Stdout,
	Formatter: new(logrus.TextFormatter),
	Hooks:     make(logrus.LevelHooks),
	Level:     logrus.DebugLevel,
}

// Initialize an in-memory cache with default expiration and cleanup interval.
var fileMetadataCache = cache.New(5*time.Minute, 10*time.Minute) // 5 minutes expiration, 10 minutes cleanup interval

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

// WriteFile writes the given data to the specified file path.
func writeFile(filePath string, data []byte) error {
	// Open the file for writing
	file, err := os.Create(filePath)
	if err != nil {
		log.Errorf("Error creating file: %s, error: %v", filePath, err)
		return err
	}
	defer file.Close()

	// Write the data to the file
	_, err = file.Write(data)
	if err != nil {
		log.Errorf("Error writing to file: %s, error: %v", filePath, err)
		return err
	}
	log.Infof("Successfully wrote file: %s", filePath)
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
		// Read the body data
		data, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Errorf("Error reading body: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		log.Infof("Received %d bytes of data for path: %s", len(data), filePath)

		// Write the file
		if err := writeFile(filePath, data); err != nil {
			log.Errorf("Failed to write file: %s, error: %v", filePath, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		log.Infof("File successfully uploaded: %s", filePath)
		return
	}

	// Handle GET or HEAD request (serve file)
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

// Check if a path is rate-limited or banned
func isRateLimitedOrBanned(path string) bool {
	if value, exists := rateLimits.Load(path); exists {
		rateLimit := value.(*RateLimit)
		if rateLimit.banned {
			if conf.AutoUnban && time.Now().After(rateLimit.blockExpires) {
				rateLimit.banned = false
				rateLimit.failedAttempts = 0
				log.Infof("Auto-unbanned path: %s", path)
				return false
			}
			return true
		}
		if time.Now().Before(rateLimit.blockExpires) {
			return true
		}
		rateLimit.failedAttempts = 0
	}
	return false
}

// Update failed attempts and potentially ban or block the path
func updateFailedAttempts(path string) {
	value, _ := rateLimits.LoadOrStore(path, &RateLimit{})
	rateLimit := value.(*RateLimit)

	rateLimit.failedAttempts++

	if rateLimit.failedAttempts >= conf.BlockAfterFails {
		rateLimit.blockExpires = time.Now().Add(time.Duration(conf.AutoBanTime) * time.Second)
		rateLimit.banned = true
		log.Warnf("Banning path %s for %d seconds due to too many failed attempts", path, conf.AutoBanTime)
	}
}

// Function to periodically reask for the HMAC secret
func reaskHMACSecret() {
	interval, err := time.ParseDuration(conf.ReaskSecretInterval)
	if err != nil {
		log.Fatalf("Invalid ReaskSecretInterval: %v", err)
	}

	for {
		time.Sleep(interval)

		// Logic to reask for the HMAC secret
		log.Info("Reasking for HMAC secret...")

		// Here, implement the logic to get a new secret (could be from user input, a config file, etc.)
		// Example: update `conf.Secret` with a new value.
		// conf.Secret = getNewSecretFromUser() // Pseudocode
	}
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
		
		subpath := path.Join("/", conf.UploadSubDir)
		subpath = strings.TrimRight(subpath, "/")
		subpath += "/"
		http.HandleFunc(subpath, handleRequest)
		log.Printf("Server started on %s. Waiting for requests.\n", address)

		setLogLevel()

		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// Start reasking for HMAC secret if enabled
	if conf.ReaskSecretEnabled {
		go reaskHMACSecret()
	}

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	if err := srv.Shutdown(nil); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}
}
