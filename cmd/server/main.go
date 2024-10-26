package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"runtime"

	"github.com/BurntSushi/toml"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// Global variables
var conf Config
var versionString = "v2.0"
var log = logrus.New()

// Prometheus metrics
var (
	uploadDuration      = prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: "hmac", Name: "file_server_upload_duration_seconds", Help: "Histogram of file upload duration in seconds.", Buckets: prometheus.DefBuckets})
	uploadErrorsTotal   = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "hmac", Name: "file_server_upload_errors_total", Help: "Total number of file upload errors."})
	uploadsTotal        = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "hmac", Name: "file_server_uploads_total", Help: "Total number of successful file uploads."})
	downloadDuration    = prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: "hmac", Name: "file_server_download_duration_seconds", Help: "Histogram of file download duration in seconds.", Buckets: prometheus.DefBuckets})
	downloadsTotal      = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "hmac", Name: "file_server_downloads_total", Help: "Total number of successful file downloads."})
	downloadErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "hmac", Name: "file_server_download_errors_total", Help: "Total number of file download errors."})
)

// Configuration struct
type Config struct {
	ListenPort              string
	UnixSocket              bool
	Secret                  string
	StoreDir                string
	UploadSubDir            string
	LogLevel                string
	LogFile                 string
	MetricsEnabled          bool
	MetricsPort             string
	FileTTL                 string
	ResumableUploadsEnabled bool
	EnableVersioning        bool
	MaxVersions             int
	ChunkingEnabled         bool
	ChunkSize               int64
}

// UploadTask struct
type UploadTask struct {
	AbsFilename   string
	FileStorePath string
	Writer        http.ResponseWriter
	Request       *http.Request
	Done          chan error
}

const (
	NumWorkers      = 10
	UploadQueueSize = 1000
)

var uploadQueue chan UploadTask

// Read configuration from config.toml
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

	// Set default settings
	if conf.ChunkSize == 0 {
		conf.ChunkSize = 4096 // Default chunk size of 4KB
	}

	return nil
}

// Setup logging
func setupLogging() {
	level, err := logrus.ParseLevel(conf.LogLevel)
	if err != nil {
		log.Fatalf("Invalid log level: %s", conf.LogLevel)
	}
	log.SetLevel(level)

	if conf.LogFile != "" {
		logFile, err := os.OpenFile(conf.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		log.SetOutput(io.MultiWriter(os.Stdout, logFile))
	} else {
		log.SetOutput(os.Stdout)
	}
}

// Log system information
func logSystemInfo() {
	log.Info("========================================")
	log.Info("       HMAC File Server - v2.0          ")
	log.Info("  Secure File Handling with HMAC Auth   ")
	log.Info("========================================")

	log.Infof("Operating System: %s", runtime.GOOS)
	log.Infof("Architecture: %s", runtime.GOARCH)
	log.Infof("Number of CPUs: %d", runtime.NumCPU())
	log.Infof("Go Version: %s", runtime.Version())
}

// Adds CORS headers
func addCORSheaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET, PUT, HEAD")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "7200")
}

// Check if file exists and return its size
func fileExists(filePath string) (bool, int64) {
	fileInfo, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return false, 0
	}
	return true, fileInfo.Size()
}

// Handle chunked uploads
func handleChunkedUpload(absFilename string, w http.ResponseWriter, r *http.Request) error {
	log.Infof("Handling chunked upload for %s", absFilename)

	targetFile, err := os.OpenFile(absFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Error("Failed to open file for chunked upload:", err)
		return err
	}
	defer targetFile.Close()

	writer := bufio.NewWriter(targetFile)
	buffer := make([]byte, conf.ChunkSize)
	for {
		n, err := r.Body.Read(buffer)
		if n > 0 {
			_, writeErr := writer.Write(buffer[:n])
			if writeErr != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				log.Error("Failed to write chunk to file:", writeErr)
				return writeErr
			}
		}
		if err != nil {
			if err == io.EOF {
				break // Finished reading the body
			}
			log.Error("Error reading from request body:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return err
		}
	}

	err = writer.Flush()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Error("Failed to flush buffer to file:", err)
		return err
	}

	uploadsTotal.Inc()
	w.WriteHeader(http.StatusCreated)
	return nil
}

// Process uploads
func processUpload(task UploadTask) error {
	absFilename := task.AbsFilename
	w := task.Writer
	r := task.Request

	// Handle file upload logic
	if r.Method == http.MethodPut {
		return handleChunkedUpload(absFilename, w, r)
	}
	return nil
}

// Upload worker to process upload tasks
func uploadWorker() {
	for task := range uploadQueue {
		err := processUpload(task)
		task.Done <- err
		close(task.Done)
	}
}

// Handle incoming HTTP requests
func handleRequest(w http.ResponseWriter, r *http.Request) {
	log.Info("Incoming request: ", r.Method, r.URL.String())

	// Parse URL
	p := r.URL.Path
	fileStorePath := strings.TrimPrefix(p, "/"+conf.UploadSubDir)
	absFilename := filepath.Join(conf.StoreDir, fileStorePath)

	// Add CORS headers
	addCORSheaders(w)

	if r.Method == http.MethodPut {
		done := make(chan error)
		task := UploadTask{
			AbsFilename:   absFilename,
			FileStorePath: fileStorePath,
			Writer:        w,
			Request:       r,
			Done:          done,
		}

		select {
		case uploadQueue <- task:
		default:
			log.Warn("Upload queue is full. Rejecting upload.")
			http.Error(w, "Server busy. Try again later.", http.StatusServiceUnavailable)
			uploadErrorsTotal.Inc()
			return
		}

		err := <-done
		if err != nil {
			uploadErrorsTotal.Inc()
			return
		}
		return
	} else if r.Method == http.MethodGet {
		fileInfo, err := os.Stat(absFilename)
		if err != nil {
			log.Error("Getting file information failed:", err)
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		contentType := mime.TypeByExtension(filepath.Ext(fileStorePath))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		w.Header().Set("Content-Type", contentType)

		http.ServeFile(w, r, absFilename)
		return
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

// Main function
func main() {
	var configFile string
	flag.StringVar(&configFile, "config", "./config.toml", "Path to configuration file \"config.toml\".")
	flag.Parse()

	err := readConfig(configFile, &conf)
	if err != nil {
		log.Fatalln("There was an error while reading the configuration file:", err)
	}

	err = os.MkdirAll(conf.StoreDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Could not create directory %s: %v", conf.StoreDir, err)
	}
	log.Infof("Directory %s is ready", conf.StoreDir)

	setupLogging()
	logSystemInfo()

	uploadQueue = make(chan UploadTask, UploadQueueSize)

	// Start workers
	for i := 0; i < NumWorkers; i++ {
		go uploadWorker()
	}

	proto := "tcp"
	if conf.UnixSocket {
		proto = "unix"
	}

	if conf.MetricsEnabled {
		prometheus.MustRegister(uploadDuration, uploadErrorsTotal, uploadsTotal)
		prometheus.MustRegister(downloadDuration, downloadsTotal, downloadErrorsTotal)

		go func() {
			http.Handle("/metrics", promhttp.Handler())
			log.Printf("Starting metrics server on %s", conf.MetricsPort)
			if err := http.ListenAndServe(conf.MetricsPort, nil); err != nil {
				log.Fatalf("Metrics server failed: %v", err)
			}
		}()
	}

	log.Println("Starting HMAC file server", versionString, "...")
	listener, err := net.Listen(proto, conf.ListenPort)
	if err != nil {
		log.Fatalln("Could not open listening socket:", err)
	}

	subpath := filepath.Join("/", conf.UploadSubDir)
	http.HandleFunc(subpath, handleRequest)

	log.Printf("Server started on port %s. Waiting for requests.\n", conf.ListenPort)

	// Setup graceful shutdown
	setupGracefulShutdown()
	http.Serve(listener, nil)
}

// Setup graceful shutdown
func setupGracefulShutdown() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Println("Shutting down server...")
		close(uploadQueue)
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}()
}
