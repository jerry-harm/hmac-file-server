package main

import (
	"bufio"
	"context"
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
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"runtime"

	"github.com/BurntSushi/toml"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	"github.com/sirupsen/logrus"
	"github.com/patrickmn/go-cache"
)

var conf Config
var versionString string = "v2.0.2"
var log = logrus.New()

// Prometheus metrics
var (
	uploadDuration      = prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: "hmac", Name: "file_server_upload_duration_seconds", Help: "Histogram of file upload duration in seconds.", Buckets: prometheus.DefBuckets})
	uploadErrorsTotal   = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "hmac", Name: "file_server_upload_errors_total", Help: "Total number of file upload errors."})
	uploadsTotal        = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "hmac", Name: "file_server_uploads_total", Help: "Total number of successful file uploads."})
	downloadDuration    = prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: "hmac", Name: "file_server_download_duration_seconds", Help: "Histogram of file download duration in seconds.", Buckets: prometheus.DefBuckets})
	downloadsTotal      = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "hmac", Name: "file_server_downloads_total", Help: "Total number of successful file downloads."})
	downloadErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "hmac", Name: "file_server_download_errors_total", Help: "Total number of file download errors."})
	memoryUsage         = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "hmac", Name: "memory_usage_bytes", Help: "Current memory usage in bytes."})
	cpuUsage            = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "hmac", Name: "cpu_usage_percent", Help: "Current CPU usage as a percentage."})
	activeConnections   = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "hmac", Name: "active_connections_total", Help: "Total number of active connections."})
	requestsTotal       = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "hmac", Name: "http_requests_total", Help: "Total number of HTTP requests received, labeled by method and path."}, []string{"method", "path"})
	goroutines          = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "hmac", Name: "goroutines_count", Help: "Current number of goroutines."})
	uploadSizeBytes     = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "hmac",
		Name:      "file_server_upload_size_bytes",
		Help:      "Histogram of uploaded file sizes in bytes.",
		Buckets:   prometheus.ExponentialBuckets(100, 10, 8),
	})
	downloadSizeBytes = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "hmac",
		Name:      "file_server_download_size_bytes",
		Help:      "Histogram of downloaded file sizes in bytes.",
		Buckets:   prometheus.ExponentialBuckets(100, 10, 8),
	})
)

// Configuration struct
type Config struct {
	ListenPort                string
	UnixSocket                bool
	Secret                    string
	StoreDir                  string
	UploadSubDir              string
	LogLevel                  string
	LogFile                   string
	MetricsEnabled            bool
	MetricsPort               string
	FileTTL                   string   // Optional TTL for file expiration (default: "30d")
	ResumableUploadsEnabled   bool     // Enable or disable resumable uploads
	ResumableDownloadsEnabled bool     // Enable or disable resumable downloads
	EnableVersioning          bool     // Enable file versioning
	MaxVersions               int      // Maximum number of file versions to keep
	ChunkingEnabled           bool     // Enable or disable chunking
	ChunkSize                 int64    // Size of each chunk in bytes
	AllowedExtensions         []string // List of allowed file extensions (e.g., [".txt", ".jpg"])
}

// UploadTask struct
type UploadTask struct {
	AbsFilename   string
	FileStorePath string
	Writer        http.ResponseWriter
	Request       *http.Request
	Done          chan error
}

// Event struct for network changes
type NetworkEvent struct {
	Type    string
	Details string
}

// Channel for network events
var networkEvents = make(chan NetworkEvent, 100)

// Upload queue constants
const (
	MinWorkers          = 10
	MaxWorkers          = 100
	UploadQueueSize     = 5000
	networkPollInterval = 10 * time.Second
)

// Upload queue
var uploadQueue chan UploadTask

// File info cache
var fileInfoCache *cache.Cache

// Read configuration from config.toml with default values for optional settings
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

	// Set defaults for optional settings
	if !conf.ResumableUploadsEnabled {
		conf.ResumableUploadsEnabled = false
	}
	if !conf.ResumableDownloadsEnabled {
		conf.ResumableDownloadsEnabled = false
	}
	if conf.MaxVersions == 0 {
		conf.MaxVersions = 0 // Default to no maximum versions
	}
	if !conf.EnableVersioning {
		conf.EnableVersioning = false // Default to not enabling versioning
	}
	if !conf.ChunkingEnabled {
		conf.ChunkingEnabled = false // Default to not enabling chunking
	}
	if conf.ChunkSize == 0 {
		conf.ChunkSize = 1048576 // Default chunk size of 1MB
	}
	if conf.AllowedExtensions == nil {
		conf.AllowedExtensions = []string{} // Default to no restrictions
	}

	return nil
}

// Setup logging function
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

	// Use JSON formatter for structured logging
	log.SetFormatter(&logrus.JSONFormatter{})
}

// Log system information with a banner
func logSystemInfo() {
	log.Info("========================================")
	log.Info("       HMAC File Server - v2.0          ")
	log.Info("  Secure File Handling with HMAC Auth   ")
	log.Info("========================================")

	log.Info("Features: Redis, Fallback Database (PostgreSQL/MySQL), Prometheus Metrics")
	log.Info("Build Date: 2024-10-23")

	log.Infof("Operating System: %s", runtime.GOOS)
	log.Infof("Architecture: %s", runtime.GOARCH)
	log.Infof("Number of CPUs: %d", runtime.NumCPU())
	log.Infof("Go Version: %s", runtime.Version())

	v, _ := mem.VirtualMemory()
	log.Infof("Total Memory: %v MB", v.Total/1024/1024)
	log.Infof("Free Memory: %v MB", v.Free/1024/1024)
	log.Infof("Used Memory: %v MB", v.Used/1024/1024)

	cpuInfo, _ := cpu.Info()
	for _, info := range cpuInfo {
		log.Infof("CPU Model: %s, Cores: %d, Mhz: %f", info.ModelName, info.Cores, info.Mhz)
	}

	partitions, _ := disk.Partitions(false)
	for _, partition := range partitions {
		usage, _ := disk.Usage(partition.Mountpoint)
		log.Infof("Disk Mountpoint: %s, Total: %v GB, Free: %v GB, Used: %v GB",
			partition.Mountpoint, usage.Total/1024/1024/1024, usage.Free/1024/1024/1024, usage.Used/1024/1024/1024)
	}

	hInfo, _ := host.Info()
	log.Infof("Hostname: %s", hInfo.Hostname)
	log.Infof("Uptime: %v seconds", hInfo.Uptime)
	log.Infof("Boot Time: %v", time.Unix(int64(hInfo.BootTime), 0))
	log.Infof("Platform: %s", hInfo.Platform)
	log.Infof("Platform Family: %s", hInfo.PlatformFamily)
	log.Infof("Platform Version: %s", hInfo.PlatformVersion)
	log.Infof("Kernel Version: %s", hInfo.KernelVersion)
}

// Initialize Prometheus metrics
func initMetrics() {
	if conf.MetricsEnabled {
		prometheus.MustRegister(uploadDuration, uploadErrorsTotal, uploadsTotal)
		prometheus.MustRegister(downloadDuration, downloadsTotal, downloadErrorsTotal)
		prometheus.MustRegister(memoryUsage, cpuUsage, activeConnections, requestsTotal, goroutines)
		prometheus.MustRegister(uploadSizeBytes, downloadSizeBytes)
	}
}

// Update system metrics periodically
func updateSystemMetrics(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping system metrics updater.")
			return
		case <-ticker.C:
			v, _ := mem.VirtualMemory()
			memoryUsage.Set(float64(v.Used))

			cpuPercent, _ := cpu.Percent(0, false)
			if len(cpuPercent) > 0 {
				cpuUsage.Set(cpuPercent[0])
			}

			goroutines.Set(float64(runtime.NumGoroutine()))
		}
	}
}

// Sets CORS headers
func addCORSheaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET, PUT, HEAD")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "7200")
}

// Function to check if file exists and return its size
func fileExists(filePath string) (bool, int64) {
	if cachedInfo, found := fileInfoCache.Get(filePath); found {
		if info, ok := cachedInfo.(os.FileInfo); ok {
			return !info.IsDir(), info.Size()
		}
	}

	fileInfo, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return false, 0
	} else if err != nil {
		log.Error("Error checking file existence:", err)
		return false, 0
	}

	fileInfoCache.Set(filePath, fileInfo, cache.DefaultExpiration)
	return !fileInfo.IsDir(), fileInfo.Size()
}

// Function to check if the file extension is allowed
func isExtensionAllowed(filename string) bool {
	if len(conf.AllowedExtensions) == 0 {
		return true // No restrictions if the list is empty
	}
	ext := strings.ToLower(filepath.Ext(filename))
	for _, allowedExt := range conf.AllowedExtensions {
		if strings.ToLower(allowedExt) == ext {
			return true
		}
	}
	return false
}

// Handle file versioning by moving the existing file to a versioned directory
func versionFile(absFilename string) error {
	versionDir := absFilename + "_versions"

	err := os.MkdirAll(versionDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create version directory: %v", err)
	}

	timestamp := time.Now().Format("20060102-150405")
	versionedFilename := filepath.Join(versionDir, filepath.Base(absFilename)+"."+timestamp)

	err = os.Rename(absFilename, versionedFilename)
	if err != nil {
		return fmt.Errorf("failed to version the file: %v", err)
	}

	log.WithFields(logrus.Fields{
		"original":     absFilename,
		"versioned_as": versionedFilename,
	}).Info("Versioned old file")
	return cleanupOldVersions(versionDir)
}

// Clean up older versions if they exceed the maximum allowed
func cleanupOldVersions(versionDir string) error {
	files, err := os.ReadDir(versionDir)
	if err != nil {
		return fmt.Errorf("failed to list version files: %v", err)
	}

	if len(files) > conf.MaxVersions {
		excessFiles := len(files) - conf.MaxVersions
		for i := 0; i < excessFiles; i++ {
			err := os.Remove(filepath.Join(versionDir, files[i].Name()))
			if err != nil {
				return fmt.Errorf("failed to remove old version: %v", err)
			}
			log.WithField("file", files[i].Name()).Info("Removed old version")
		}
	}

	return nil
}

// Handle chunked uploads (using bufio.Writer)
func handleChunkedUpload(absFilename string, w http.ResponseWriter, r *http.Request) error {
	log.WithField("file", absFilename).Info("Handling chunked upload")

	targetFile, err := os.OpenFile(absFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.WithError(err).Error("Failed to open file for chunked upload")
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
				log.WithError(writeErr).Error("Failed to write chunk to file")
				return writeErr
			}
		}
		if err != nil {
			if err == io.EOF {
				break // Finished reading the body
			}
			log.WithError(err).Error("Error reading from request body")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return err
		}
	}

	err = writer.Flush()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.WithError(err).Error("Failed to flush buffer to file")
		return err
	}

	uploadSizeBytes.Observe(float64(r.ContentLength))
	uploadsTotal.Inc()
	w.WriteHeader(http.StatusCreated)
	return nil
}

// ProcessUpload function to handle upload tasks
func processUpload(task UploadTask) error {
	absFilename := task.AbsFilename
	fileStorePath := task.FileStorePath
	w := task.Writer
	r := task.Request

	startTime := time.Now()

	// Handle chunked upload if enabled
	if conf.ChunkingEnabled {
		err := handleChunkedUpload(absFilename, w, r)
		if err != nil {
			uploadDuration.Observe(time.Since(startTime).Seconds())
			return err
		}
		uploadDuration.Observe(time.Since(startTime).Seconds())
		return nil
	}

	// File versioning logic
	if conf.EnableVersioning {
		existing, _ := fileExists(absFilename)
		if existing {
			err := versionFile(absFilename)
			if err != nil {
				log.WithError(err).Error("Error versioning file")
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				uploadDuration.Observe(time.Since(startTime).Seconds())
				return err
			}
		}
	}

	// Proceed to create the file after successful HMAC validation
	err := createFile(absFilename, fileStorePath, w, r)
	if err != nil {
		log.WithError(err).Error("Error creating file")
		uploadDuration.Observe(time.Since(startTime).Seconds())
		return err
	}

	uploadDuration.Observe(time.Since(startTime).Seconds())
	return nil
}

// Worker function to process upload tasks
func uploadWorker(ctx context.Context, workerID int) {
	log.WithField("worker_id", workerID).Info("Upload worker started")
	for {
		select {
		case <-ctx.Done():
			log.WithField("worker_id", workerID).Info("Upload worker stopping")
			return
		case task, ok := <-uploadQueue:
			if !ok {
				log.WithField("worker_id", workerID).Info("Upload queue closed")
				return
			}
			err := processUpload(task)
			if err != nil {
				uploadErrorsTotal.Inc()
				// Optionally, implement retry logic here
			}
			task.Done <- err
			close(task.Done)
		}
	}
}

// Handle incoming HTTP requests, including HMAC validation and file uploads/downloads
func handleRequest(w http.ResponseWriter, r *http.Request) {
	log.WithFields(logrus.Fields{
		"method": r.Method,
		"url":    r.URL.String(),
		"remote": r.RemoteAddr,
	}).Info("Incoming request")

	// Parse URL and args
	p := r.URL.Path
	a, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		log.Warn("Failed to parse query parameters")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	subDir := path.Join("/", conf.UploadSubDir)
	fileStorePath := strings.TrimPrefix(p, subDir)
	if fileStorePath == "" || fileStorePath == "/" {
		log.Warn("Access to root directory is forbidden")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	} else if fileStorePath[0] == '/' {
		fileStorePath = fileStorePath[1:]
	}

	absFilename := filepath.Join(conf.StoreDir, fileStorePath)

	// Add CORS headers
	addCORSheaders(w)

	switch r.Method {
	case http.MethodPut:
		handleUpload(w, r, absFilename, fileStorePath, a)
	case http.MethodHead, http.MethodGet:
		handleDownload(w, r, absFilename, fileStorePath)
	case http.MethodOptions:
		w.Header().Set("Allow", "OPTIONS, GET, PUT, HEAD")
		return
	default:
		log.WithField("method", r.Method).Warn("Invalid HTTP method for upload directory")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
}

// Handle file uploads with extension restrictions
func handleUpload(w http.ResponseWriter, r *http.Request, absFilename, fileStorePath string, a url.Values) {
	// Determine protocol version based on query parameters
	var protocolVersion string
	if a.Get("v2") != "" {
		protocolVersion = "v2"
	} else if a.Get("token") != "" {
		protocolVersion = "token"
	} else if a.Get("v") != "" {
		protocolVersion = "v"
	} else {
		log.Warn("No HMAC attached to URL. Expecting 'v', 'v2', or 'token' parameter as MAC")
		http.Error(w, "No HMAC attached to URL. Expecting 'v', 'v2', or 'token' parameter as MAC", http.StatusForbidden)
		return
	}

	// Initialize HMAC
	mac := hmac.New(sha256.New, []byte(conf.Secret))

	// Calculate MAC based on protocolVersion
	if protocolVersion == "v" {
		mac.Write([]byte(fileStorePath + "\x20" + strconv.FormatInt(r.ContentLength, 10)))
	} else if protocolVersion == "v2" || protocolVersion == "token" {
		contentType := mime.TypeByExtension(filepath.Ext(fileStorePath))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		mac.Write([]byte(fileStorePath + "\x00" + strconv.FormatInt(r.ContentLength, 10) + "\x00" + contentType))
	}

	calculatedMAC := mac.Sum(nil)

	// Decode provided MAC from hex
	providedMAC, err := hex.DecodeString(a.Get(protocolVersion))
	if err != nil {
		log.Warn("Invalid MAC encoding")
		http.Error(w, "Invalid MAC encoding", http.StatusForbidden)
		return
	}

	// Validate the HMAC
	if !hmac.Equal(calculatedMAC, providedMAC) {
		log.Warn("Invalid MAC")
		http.Error(w, "Invalid MAC", http.StatusForbidden)
		return
	}

	// Validate file extension
	if !isExtensionAllowed(fileStorePath) {
		log.WithFields(logrus.Fields{
			"filename":  fileStorePath,
			"extension": filepath.Ext(fileStorePath),
		}).Warn("Attempted upload with disallowed file extension")
		http.Error(w, "Disallowed file extension. Allowed extensions are: "+strings.Join(conf.AllowedExtensions, ", "), http.StatusForbidden)
		uploadErrorsTotal.Inc()
		return
	}

	// Create an UploadTask with a done channel
	done := make(chan error)
	task := UploadTask{
		AbsFilename:   absFilename,
		FileStorePath: fileStorePath,
		Writer:        w,
		Request:       r,
		Done:          done,
	}

	// Submit task to the upload queue
	select {
	case uploadQueue <- task:
		// Successfully added to the queue
		log.Debug("Upload task enqueued successfully")
	default:
		// Queue is full
		log.Warn("Upload queue is full. Rejecting upload")
		http.Error(w, "Server busy. Try again later.", http.StatusServiceUnavailable)
		uploadErrorsTotal.Inc()
		return
	}

	// Wait for the worker to process the upload
	err = <-done
	if err != nil {
		// The worker has already sent an appropriate HTTP error response
		return
	}

	// Upload was successful; response has been handled by the worker
}

// Create the file for upload with buffered Writer
func createFile(absFilename, fileStorePath string, w http.ResponseWriter, r *http.Request) error {
	absDirectory := filepath.Dir(absFilename)
	err := os.MkdirAll(absDirectory, os.ModePerm)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return fmt.Errorf("failed to create directory %s: %w", absDirectory, err)
	}

	targetFile, err := os.OpenFile(absFilename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		http.Error(w, "Conflict", http.StatusConflict)
		return fmt.Errorf("failed to create file %s: %w", absFilename, err)
	}
	defer targetFile.Close()

	writer := bufio.NewWriter(targetFile)
	buffer := make([]byte, 32*1024) // 32KB buffer
	_, err = io.CopyBuffer(writer, r.Body, buffer)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return fmt.Errorf("failed to copy file contents to %s: %w", absFilename, err)
	}

	err = writer.Flush()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return fmt.Errorf("failed to flush buffer to file %s: %w", absFilename, err)
	}

	uploadSizeBytes.Observe(float64(r.ContentLength))
	uploadsTotal.Inc()
	w.WriteHeader(http.StatusCreated)
	return nil
}

// Handle file downloads
func handleDownload(w http.ResponseWriter, r *http.Request, absFilename, fileStorePath string) {
	fileInfo, err := getFileInfo(absFilename)
	if err != nil {
		log.WithError(err).Error("Failed to get file information")
		http.Error(w, "Not Found", http.StatusNotFound)
		downloadErrorsTotal.Inc()
		return
	} else if fileInfo.IsDir() {
		log.Warn("Directory listing forbidden")
		http.Error(w, "Forbidden", http.StatusForbidden)
		downloadErrorsTotal.Inc()
		return
	}

	contentType := mime.TypeByExtension(filepath.Ext(fileStorePath))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)

	// Handle resumable downloads
	if conf.ResumableDownloadsEnabled {
		handleResumableDownload(absFilename, w, r, fileInfo.Size())
		return
	}

	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))
		downloadsTotal.Inc()
		return
	} else {
		// Measure download duration
		startTime := time.Now()
		http.ServeFile(w, r, absFilename)
		downloadDuration.Observe(time.Since(startTime).Seconds())
		downloadSizeBytes.Observe(float64(fileInfo.Size()))
		downloadsTotal.Inc()
		return
	}
}

// Get file information with caching
func getFileInfo(absFilename string) (os.FileInfo, error) {
	if cachedInfo, found := fileInfoCache.Get(absFilename); found {
		if info, ok := cachedInfo.(os.FileInfo); ok {
			return info, nil
		}
	}

	fileInfo, err := os.Stat(absFilename)
	if err != nil {
		return nil, err
	}

	fileInfoCache.Set(absFilename, fileInfo, cache.DefaultExpiration)
	return fileInfo, nil
}

// Handle resumable downloads
func handleResumableDownload(absFilename string, w http.ResponseWriter, r *http.Request, fileSize int64) {
	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		// If no Range header, serve the full file
		startTime := time.Now()
		http.ServeFile(w, r, absFilename)
		downloadDuration.Observe(time.Since(startTime).Seconds())
		downloadSizeBytes.Observe(float64(fileSize))
		downloadsTotal.Inc()
		return
	}

	// Parse Range header
	ranges := strings.Split(strings.TrimPrefix(rangeHeader, "bytes="), "-")
	if len(ranges) != 2 {
		http.Error(w, "Invalid Range", http.StatusRequestedRangeNotSatisfiable)
		downloadErrorsTotal.Inc()
		return
	}

	start, err := strconv.ParseInt(ranges[0], 10, 64)
	if err != nil {
		http.Error(w, "Invalid Range", http.StatusRequestedRangeNotSatisfiable)
		downloadErrorsTotal.Inc()
		return
	}

	// Calculate end byte
	end := fileSize - 1
	if ranges[1] != "" {
		end, err = strconv.ParseInt(ranges[1], 10, 64)
		if err != nil || end >= fileSize {
			http.Error(w, "Invalid Range", http.StatusRequestedRangeNotSatisfiable)
			downloadErrorsTotal.Inc()
			return
		}
	}

	// Set response headers for partial content
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, fileSize))
	w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusPartialContent)

	// Serve the requested byte range
	file, err := os.Open(absFilename)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		downloadErrorsTotal.Inc()
		return
	}
	defer file.Close()

	// Seek to the start byte
	_, err = file.Seek(start, 0)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		downloadErrorsTotal.Inc()
		return
	}

	// Create a buffer and copy the specified range to the response writer
	buffer := make([]byte, 32*1024) // 32KB buffer
	remaining := end - start + 1
	startTime := time.Now()
	for remaining > 0 {
		if int64(len(buffer)) > remaining {
			buffer = buffer[:remaining]
		}
		n, err := file.Read(buffer)
		if n > 0 {
			if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
				log.WithError(writeErr).Error("Failed to write to response")
				downloadErrorsTotal.Inc()
				return
			}
			remaining -= int64(n)
		}
		if err != nil {
			if err != io.EOF {
				log.WithError(err).Error("Error reading file during resumable download")
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				downloadErrorsTotal.Inc()
			}
			break
		}
	}
	downloadDuration.Observe(time.Since(startTime).Seconds())
	downloadSizeBytes.Observe(float64(end - start + 1))
	downloadsTotal.Inc()
}

// Function to handle network events
func handleNetworkEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping network event handler.")
			return
		case event, ok := <-networkEvents:
			if !ok {
				log.Info("Network events channel closed.")
				return
			}
			switch event.Type {
			case "IP_CHANGE":
				log.WithField("new_ip", event.Details).Info("Network change detected")
				// Example: Update Prometheus gauge or trigger alerts
				// activeConnections.Set(float64(getActiveConnections()))
			}
			// Additional event types can be handled here
		}
	}
}

// Function to monitor network changes
func monitorNetwork(ctx context.Context) {
	currentIP := getCurrentIPAddress() // Placeholder for initial IP address

	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping network monitor.")
			return
		case <-time.After(networkPollInterval):
			newIP := getCurrentIPAddress()
			if newIP != currentIP && newIP != "" {
				currentIP = newIP
				select {
				case networkEvents <- NetworkEvent{Type: "IP_CHANGE", Details: currentIP}:
					log.WithField("new_ip", currentIP).Info("Queued IP_CHANGE event")
				default:
					log.Warn("Network event channel is full. Dropping IP_CHANGE event.")
				}
			}
		}
	}
}

// Example function to get current IP address
func getCurrentIPAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.WithError(err).Error("Failed to get network interfaces")
		return ""
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue // Skip down or loopback interfaces
		}
		addrs, err := iface.Addrs()
		if err != nil {
			log.WithError(err).Errorf("Failed to get addresses for interface %s", iface.Name)
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.IsGlobalUnicast() && ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

// Setup graceful shutdown
func setupGracefulShutdown(server *http.Server, cancel context.CancelFunc) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Info("Shutting down server...")

		// Create a deadline to wait for.
		ctxShutdown, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(ctxShutdown); err != nil {
			log.WithError(err).Fatal("Server Shutdown Failed")
		}

		// Signal other goroutines to stop
		cancel()

		// Close the upload queue and network events channel
		close(uploadQueue)
		close(networkEvents)

		log.Info("Server gracefully stopped.")
		os.Exit(0)
	}()
}

// Initialize worker pool with dynamic scaling
func initializeWorkerPool(ctx context.Context) {
	for i := 0; i < MinWorkers; i++ {
		go uploadWorker(ctx, i)
	}
	// Dynamic scaling logic can be implemented here if needed
}

// Setup HTTP server with middleware
func setupRouter() http.Handler {
	mux := http.NewServeMux()
	subpath := path.Join("/", conf.UploadSubDir)
	subpath = strings.TrimRight(subpath, "/") + "/"
	mux.HandleFunc(subpath, handleRequest)
	if conf.MetricsEnabled {
		mux.Handle("/metrics", promhttp.Handler())
	}

	// Apply middleware
	handler := loggingMiddleware(corsMiddleware(mux))
	return handler
}

// Middleware for logging
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestsTotal.WithLabelValues(r.Method, r.URL.Path).Inc()
		next.ServeHTTP(w, r)
	})
}

// Middleware for CORS
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addCORSheaders(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
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

	// Initialize file info cache with default expiration of 5 minutes
	fileInfoCache = cache.New(5*time.Minute, 10*time.Minute)

	err = os.MkdirAll(conf.StoreDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Could not create directory %s: %v", conf.StoreDir, err)
	}
	log.WithField("directory", conf.StoreDir).Info("Store directory is ready")

	setupLogging()
	logSystemInfo()
	initMetrics()

	// Initialize the upload queue
	uploadQueue = make(chan UploadTask, UploadQueueSize)

	// Create a context for managing goroutine lifecycles
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitoring network changes and handling events
	go monitorNetwork(ctx)
	go handleNetworkEvents(ctx)

	// Start updating system metrics
	go updateSystemMetrics(ctx)

	// Initialize worker pool
	initializeWorkerPool(ctx)

	// Setup HTTP server with router
	router := setupRouter()
	server := &http.Server{
		Addr:         conf.ListenPort,
		Handler:      router,
		ReadTimeout:  10 * time.Minute, // Increased from 15s
		WriteTimeout: 10 * time.Minute, // Increased from 15s
		IdleTimeout:  2 * time.Minute,  // Adjusted as needed
	}

	// Start metrics server if enabled
	if conf.MetricsEnabled {
		go func() {
			log.Infof("Starting metrics server on %s", conf.MetricsPort)
			metricsAddr := conf.MetricsPort
			if !strings.Contains(metricsAddr, ":") {
				metricsAddr = ":" + metricsAddr
			}
			http.Handle("/metrics", promhttp.Handler())
			if err := http.ListenAndServe(metricsAddr, nil); err != nil {
				log.WithError(err).Fatal("Metrics server failed")
			}
		}()
	}

	// Setup graceful shutdown
	setupGracefulShutdown(server, cancel)

	// Start server
	log.Infof("Starting HMAC file server %s...", versionString)
	if conf.UnixSocket {
		listener, err := net.Listen("unix", conf.ListenPort)
		if err != nil {
			log.WithError(err).Fatal("Could not open Unix socket")
		}
		defer listener.Close()
		log.Infof("Server started on Unix socket %s. Waiting for requests.", conf.ListenPort)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("Server failed")
		}
	} else {
		log.Infof("Server started on port %s. Waiting for requests.", conf.ListenPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("Server failed")
		}
	}
}
