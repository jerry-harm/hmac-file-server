package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"runtime"
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

// Initialize an in-memory cache with default expiration and cleanup interval.
var fileMetadataCache = cache.New(5*time.Minute, 10*time.Minute)  // 5 minutes expiration, 10 minutes cleanup interval

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

// Request handler
func handleRequest(w http.ResponseWriter, r *http.Request) {
	if r == nil {
		log.Error("Received nil request")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

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

	// Handle file upload (if you need HMAC, implement it here)
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

// Main function
func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())  // Use all available cores

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
		TLSConfig: &tls.Config{
			NextProtos: []string{"h2", "http/1.1"}, 
		},
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

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	if err := srv.Shutdown(nil); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}
}
