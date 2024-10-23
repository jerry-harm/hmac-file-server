package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strconv"  // <-- Add this import
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/go-redis/redis/v8"
	"github.com/jackc/pgx/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	"github.com/sirupsen/logrus"
	_ "github.com/go-sql-driver/mysql"
	_ "net/http/pprof"
)

// Configuration struct with fallback options
type Config struct {
	ListenPort             string
	UnixSocket             bool
	Secret                 string
	StoreDir               string
	UploadSubDir           string
	LogLevel               string
	LogFile                string
	MaxRetries             int
	RetryDelay             int
	RedisAddr              string // Empty if Redis is not enabled
	RedisPassword          string
	RedisDB                int
	FallbackEnabled        bool   // Use fallback database (MariaDB/PostgreSQL) if true
	FallbackDBType         string // "postgres" or "mysql"
	FallbackDBHost         string
	FallbackDBUser         string
	FallbackDBPassword     string
	FallbackDBName         string
	MetricsEnabled         bool
	MetricsPort            string
	ChunkSize              int
}

var conf Config
var log = logrus.New()

// Redis client
var redisClient *redis.Client
var postgresConn *pgx.Conn
var mysqlConn *sql.DB

// Prometheus metrics
var (
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
	prometheus.MustRegister(uploadDuration, uploadErrorsTotal, uploadsTotal)
}

// Log system information with a banner
func logSystemInfo() {
	log.Info("========================================")
	log.Info("       HMAC File Server - v2.0          ")
	log.Info("  Secure File Handling with HMAC Auth   ")
	log.Info("========================================")

	log.Info("Features: Redis, Fallback Database (PostgreSQL/MySQL), Prometheus Metrics")
	log.Info("Build Date: 2024-10-23")  // Add your build date dynamically if needed
	log.Info("========================================")

	// Log basic system info
	log.Infof("Operating System: %s", runtime.GOOS)
	log.Infof("Architecture: %s", runtime.GOARCH)
	log.Infof("Number of CPUs: %d", runtime.NumCPU())
	log.Infof("Go Version: %s", runtime.Version())

	// Get memory information
	v, _ := mem.VirtualMemory()
	log.Infof("Total Memory: %v MB", v.Total/1024/1024)
	log.Infof("Free Memory: %v MB", v.Free/1024/1024)
	log.Infof("Used Memory: %v MB", v.Used/1024/1024)

	// Get host information
	hInfo, _ := host.Info()
	log.Infof("Hostname: %s", hInfo.Hostname)
	log.Infof("Uptime: %v seconds", hInfo.Uptime)
	log.Infof("Boot Time: %v", time.Unix(int64(hInfo.BootTime), 0))
	log.Infof("Platform: %s", hInfo.Platform)
	log.Infof("Platform Family: %s", hInfo.PlatformFamily)
	log.Infof("Platform Version: %s", hInfo.PlatformVersion)
	log.Infof("Kernel Version: %s", hInfo.KernelVersion)
}

// Setup logging
func setupLogging() {
	if conf.LogFile != "" {
		file, err := os.OpenFile(conf.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		writer := bufio.NewWriter(file)
		log.SetOutput(writer)

		go func() {
			for range time.Tick(5 * time.Second) {
				writer.Flush()
			}
		}()
	} else {
		log.SetOutput(os.Stdout)
	}
	log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	logSystemInfo()
}

// Initialize Redis client only once at startup
func initRedis() error {
	if conf.RedisAddr != "" {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     conf.RedisAddr,
			Password: conf.RedisPassword,
			DB:       conf.RedisDB,
		})

		_, err := redisClient.Ping(context.Background()).Result()
		if err != nil {
			log.Warn("Redis unavailable, switching to fallback.")
			return err
		}
		log.Info("Connected to Redis.")
	} else {
		log.Info("Redis not enabled, skipping Redis initialization.")
	}
	return nil
}

// Initialize PostgreSQL connection
func initPostgres() error {
	if conf.FallbackEnabled && conf.FallbackDBType == "postgres" {
		conn, err := pgx.Connect(context.Background(), fmt.Sprintf("postgresql://%s:%s@%s/%s",
			conf.FallbackDBUser, conf.FallbackDBPassword, conf.FallbackDBHost, conf.FallbackDBName))
		if err != nil {
			log.Warn("Failed to connect to PostgreSQL.")
			return err
		}
		log.Info("Connected to PostgreSQL fallback.")
		postgresConn = conn
	}
	return nil
}

// Initialize MySQL connection
func initMySQL() error {
	if conf.FallbackEnabled && conf.FallbackDBType == "mysql" {
		dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s", conf.FallbackDBUser, conf.FallbackDBPassword, conf.FallbackDBHost, conf.FallbackDBName)
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			log.Warn("Failed to connect to MySQL.")
			return err
		}
		log.Info("Connected to MySQL fallback.")
		mysqlConn = db
	}
	return nil
}

// Handle request for uploads and downloads without reconnecting to Redis
func handleRequest(w http.ResponseWriter, r *http.Request) {
	log.Info("Incoming request: ", r.Method, r.URL.String())
	addCORSheaders(w)

	// Ensure Redis is initialized only once (at startup)
	if redisClient == nil {
		log.Warn("Redis client not initialized. Redis might be down.")
		handleFallback(w, r)
		return
	}

	subDir := path.Join("/", conf.UploadSubDir)
	fileStorePath := strings.TrimPrefix(r.URL.Path, subDir)
	if fileStorePath == "" || fileStorePath == "/" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	} else if fileStorePath[0] == '/' {
		fileStorePath = fileStorePath[1:]
	}

	absFilename := filepath.Join(conf.StoreDir, fileStorePath)

	if r.Method == http.MethodPut {
		handleUpload(w, r, absFilename, fileStorePath)
	} else if r.Method == http.MethodGet || r.Method == http.MethodHead {
		serveFile(w, r, absFilename)
	} else if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, PUT, OPTIONS")
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Handle uploads with HMAC validation and chunking support
func handleUpload(w http.ResponseWriter, r *http.Request, absFilename string, fileStorePath string) {
	a, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	mac := hmac.New(sha256.New, []byte(conf.Secret))
	mac.Write([]byte(fileStorePath + "\x20" + strconv.FormatInt(r.ContentLength, 10)))
	macString := hex.EncodeToString(mac.Sum(nil))

	if hmac.Equal([]byte(macString), []byte(a["v"][0])) {
		// Check for chunked upload via headers
		if chunkID := r.Header.Get("X-Chunk-ID"); chunkID != "" {
			handleChunkedUpload(absFilename, w, r, chunkID)
		} else {
			// Handle normal upload
			createFile(absFilename, w, r)
		}
	} else {
		http.Error(w, "Forbidden", http.StatusForbidden)
	}
}

// Handle chunked upload logic
func handleChunkedUpload(absFilename string, w http.ResponseWriter, r *http.Request, chunkID string) {
	totalChunks := r.Header.Get("X-Total-Chunks")

	// Append chunk to file
	appendToFile(absFilename, w, r)

	// If it's the last chunk, complete the upload process
	if chunkID == totalChunks {
		log.Infof("All chunks received for file: %s", absFilename)
		uploadsTotal.Inc()
	}
}

// Append chunk to the file
func appendToFile(absFilename string, w http.ResponseWriter, r *http.Request) {
	// Open file in append mode
	targetFile, err := os.OpenFile(absFilename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		http.Error(w, "Conflict", http.StatusConflict)
		return
	}
	defer targetFile.Close()

	_, err = io.Copy(targetFile, r.Body)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Create a new file during normal upload
func createFile(absFilename string, w http.ResponseWriter, r *http.Request) {
	err := os.MkdirAll(filepath.Dir(absFilename), os.ModePerm)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	targetFile, err := os.OpenFile(absFilename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		http.Error(w, "Conflict", http.StatusConflict)
		return
	}
	defer targetFile.Close()

	_, err = io.Copy(targetFile, r.Body)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	uploadsTotal.Inc()
	w.WriteHeader(http.StatusCreated)
}

// Serve file for GET or HEAD requests with caching
func serveFile(w http.ResponseWriter, r *http.Request, absFilename string) {
	fileInfo, err := os.Stat(absFilename)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	} else if fileInfo.IsDir() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Set Cache-Control header for caching
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
	w.Header().Set("Last-Modified", fileInfo.ModTime().UTC().Format(http.TimeFormat))

	// Optionally add ETag for client-side cache validation
	etag := fmt.Sprintf("%x", fileInfo.ModTime().UnixNano())
	w.Header().Set("ETag", etag)

	// Handle If-Modified-Since header to avoid serving the file if it's not changed
	if since := r.Header.Get("If-Modified-Since"); since != "" {
		t, err := time.Parse(http.TimeFormat, since)
		if err == nil && fileInfo.ModTime().Before(t.Add(1*time.Second)) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	// Handle If-None-Match (ETag validation)
	if match := r.Header.Get("If-None-Match"); match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	// Set Content-Type header based on file extension
	contentType := mime.TypeByExtension(filepath.Ext(absFilename))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)

	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))
	} else {
		http.ServeFile(w, r, absFilename)
	}
}

// Set CORS headers
func addCORSheaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "7200")
}

// Fallback logic when Redis is unavailable
func handleFallback(w http.ResponseWriter, r *http.Request) {
	if conf.FallbackEnabled {
		if conf.FallbackDBType == "postgres" {
			log.Info("Using PostgreSQL fallback database...")
			query := `INSERT INTO uploads (file_name, timestamp) VALUES ($1, $2)`
			_, err := postgresConn.Exec(context.Background(), query, "example.txt", time.Now())
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
		} else if conf.FallbackDBType == "mysql" {
			log.Info("Using MySQL fallback database...")
			query := `INSERT INTO uploads (file_name, timestamp) VALUES (?, ?)`
			stmt, err := mysqlConn.Prepare(query)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			_, err = stmt.Exec("example.txt", time.Now())
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
		}
	} else {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}
}

// Main function
func main() {
	var configFile string
	var proto string

	fmt.Println("Starting HMAC File Server - v2.0...")

	flag.StringVar(&configFile, "config", "./config.toml", "Path to configuration file.")
	flag.Parse()

	fmt.Println("Reading configuration from:", configFile)

	if err := readConfig(configFile, &conf); err != nil {
		fmt.Println("Error reading config:", err)
		log.Fatalln("Error reading config:", err)
	}

	fmt.Println("Configuration loaded successfully.")

	// Setup logging
	setupLogging()
	fmt.Println("Logging setup completed.")

	// Initialize Redis if configured
	if conf.RedisAddr != "" {
		fmt.Println("Initializing Redis...")
		if err := initRedis(); err != nil {
			fmt.Println("Failed to initialize Redis:", err)
		} else {
			fmt.Println("Redis initialized successfully.")
		}
	}

	// Initialize fallback database if enabled
	if conf.FallbackEnabled {
		fmt.Println("Initializing fallback database...")
		if conf.FallbackDBType == "postgres" {
			if err := initPostgres(); err != nil {
				fmt.Println("Failed to initialize PostgreSQL:", err)
				log.Fatalln("Could not connect to PostgreSQL fallback database:", err)
			} else {
				fmt.Println("PostgreSQL initialized successfully.")
			}
		} else if conf.FallbackDBType == "mysql" {
			if err := initMySQL(); err != nil {
				fmt.Println("Failed to initialize MySQL:", err)
				log.Fatalln("Could not connect to MySQL fallback database:", err)
			} else {
				fmt.Println("MySQL initialized successfully.")
			}
		}
	}

	// Check network listener initialization
	if conf.UnixSocket {
		proto = "unix"
	} else {
		proto = "tcp"
	}

	fmt.Println("Attempting to open listener on:", conf.ListenPort)
	listener, err := net.Listen(proto, conf.ListenPort)
	if err != nil {
		fmt.Println("Error opening listener:", err)
		log.Fatalln("Could not open listener:", err)
	}

	fmt.Println("Listener opened successfully on:", conf.ListenPort)

	// Start the metrics server if enabled
	if conf.MetricsEnabled {
		go func() {
			fmt.Println("Starting metrics server on:", conf.MetricsPort)
			http.Handle("/metrics", promhttp.Handler())
			log.Printf("Metrics server listening on %s", conf.MetricsPort)
			if err := http.ListenAndServe(conf.MetricsPort, nil); err != nil {
				fmt.Println("Metrics server failed:", err)
				log.Fatalf("Metrics server failed: %v", err)
			}
		}()
	}

	subpath := path.Join("/", conf.UploadSubDir)
	subpath = strings.TrimRight(subpath, "/") + "/"
	http.HandleFunc(subpath, handleRequest)

	// Graceful shutdown handling
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		fmt.Println("Shutting down server...")
		listener.Close()
		fmt.Println("Server stopped.")
	}()

	fmt.Printf("Server started on %s. Waiting for requests.\n", conf.ListenPort)
	err = http.Serve(listener, nil)
	if err != nil {
		fmt.Println("HTTP server error:", err)
	}
}

// Read config from TOML
func readConfig(configFile string, config *Config) error {
	_, err := toml.DecodeFile(configFile, config)
	return err
}
