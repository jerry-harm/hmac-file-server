package main

import (
    "bufio"
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
)

var conf Config
var versionString string = "v2.0.1"
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
    FileTTL                 string  // Optional TTL for file expiration (default: "30d")
    ResumableUploadsEnabled bool    // Enable or disable resumable uploads
    ResumableDownloadsEnabled bool   // Enable or disable resumable downloads
    EnableVersioning        bool    // Enable file versioning
    MaxVersions             int     // Maximum number of file versions to keep
    ChunkingEnabled         bool    // Enable or disable chunking
    ChunkSize               int64   // Size of each chunk in bytes
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
    NumWorkers      = 20   // Number of workers
    UploadQueueSize = 5000 // Size of the queue
)

var uploadQueue chan UploadTask

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

/*
 * Sets CORS headers
 */
func addCORSheaders(w http.ResponseWriter) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET, PUT, HEAD")
    w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
    w.Header().Set("Access-Control-Allow-Credentials", "true")
    w.Header().Set("Access-Control-Max-Age", "7200")
}

// Function to check if file exists and return its size
func fileExists(filePath string) (bool, int64) {
    fileInfo, err := os.Stat(filePath)
    if os.IsNotExist(err) {
        return false, 0
    }
    return true, fileInfo.Size()
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

    log.Infof("Versioned old file: %s to %s", absFilename, versionedFilename)
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
            log.Infof("Removed old version: %s", files[i].Name())
        }
    }

    return nil
}

// Handle chunked uploads (using bufio.Writer)
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

// ProcessUpload function to handle upload tasks
func processUpload(task UploadTask) error {
    absFilename := task.AbsFilename
    fileStorePath := task.FileStorePath
    w := task.Writer
    r := task.Request

    // Handle chunked upload if enabled
    if conf.ChunkingEnabled {
        return handleChunkedUpload(absFilename, w, r)
    }

    // File versioning logic
    if conf.EnableVersioning {
        existing, _ := fileExists(absFilename)
        if existing {
            err := versionFile(absFilename)
            if err != nil {
                log.Errorf("Error versioning file: %v", err)
                http.Error(w, "Internal Server Error", http.StatusInternalServerError)
                return err
            }
        }
    }

    // Proceed to create the file after successful HMAC validation
    err := createFile(absFilename, fileStorePath, w, r)
    if err != nil {
        log.Error(err)
        return err
    }
    return nil
}

// Worker function to process upload tasks
func uploadWorker() {
    for task := range uploadQueue {
        err := processUpload(task)
        task.Done <- err
        close(task.Done)
    }
}

// Handle incoming HTTP requests, including HMAC validation and file uploads/downloads
func handleRequest(w http.ResponseWriter, r *http.Request) {
    log.Info("Incoming request: ", r.Method, r.URL.String())

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
        log.Warn("Access to / forbidden")
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    } else if fileStorePath[0] == '/' {
        fileStorePath = fileStorePath[1:]
    }

    absFilename := filepath.Join(conf.StoreDir, fileStorePath)

    // Add CORS headers
    addCORSheaders(w)

    if r.Method == http.MethodPut {
        // File upload logic with HMAC validation
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

        // Init HMAC
        mac := hmac.New(sha256.New, []byte(conf.Secret))
        macString := ""

        // Calculate MAC based on protocolVersion
        if protocolVersion == "v" {
            mac.Write([]byte(fileStorePath + "\x20" + strconv.FormatInt(r.ContentLength, 10)))
            macString = hex.EncodeToString(mac.Sum(nil))
        } else if protocolVersion == "v2" || protocolVersion == "token" {
            contentType := mime.TypeByExtension(filepath.Ext(fileStorePath))
            if contentType == "" {
                contentType = "application/octet-stream"
            }
            mac.Write([]byte(fileStorePath + "\x00" + strconv.FormatInt(r.ContentLength, 10) + "\x00" + contentType))
            macString = hex.EncodeToString(mac.Sum(nil))
        }

        // Validate the HMAC
        if len(a[protocolVersion]) == 0 || !hmac.Equal([]byte(macString), []byte(a[protocolVersion][0])) {
            log.Warn("Invalid MAC.")
            http.Error(w, "Invalid MAC", http.StatusForbidden)
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

        select {
        case uploadQueue <- task:
            // Successfully added to the queue
        default:
            // Queue is full
            log.Warn("Upload queue is full. Rejecting upload.")
            http.Error(w, "Server busy. Try again later.", http.StatusServiceUnavailable)
            uploadErrorsTotal.Inc()
            return
        }

        // Wait for the worker to process the upload
        err = <-done
        if err != nil {
            uploadErrorsTotal.Inc()
            // The worker has already sent an appropriate HTTP error response
            return
        }

        // Upload was successful; the worker has already sent the HTTP response
        return
    } else if r.Method == http.MethodHead || r.Method == http.MethodGet {
        // File download logic

        fileInfo, err := os.Stat(absFilename)
        if err != nil {
            log.Error("Getting file information failed:", err)
            http.Error(w, "Not Found", http.StatusNotFound)
            return
        } else if fileInfo.IsDir() {
            log.Warn("Directory listing forbidden!")
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        contentType := mime.TypeByExtension(filepath.Ext(fileStorePath))
        if contentType == "" {
            contentType = "application/octet-stream"
        }
        w.Header().Set("Content-Type", contentType)

        // Handle resumable downloads
        if conf.ResumableDownloadsEnabled {
            handleResumableDownload(absFilename, w, r)
            return
        }

        if r.Method == http.MethodHead {
            w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))
            return
        } else {
            http.ServeFile(w, r, absFilename)
            return
        }
    } else if r.Method == http.MethodOptions {
        w.Header().Set("Allow", "OPTIONS, GET, PUT, HEAD")
        return
    } else {
        log.Warn("Invalid method", r.Method, "for access to ", conf.UploadSubDir)
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
}

// Create the file for upload with buffered Writer
func createFile(absFilename string, fileStorePath string, w http.ResponseWriter, r *http.Request) error {
    absDirectory := filepath.Dir(absFilename)
    err := os.MkdirAll(absDirectory, os.ModePerm)
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return fmt.Errorf("failed to create directory %s: %s", absDirectory, err)
    }

    targetFile, err := os.OpenFile(absFilename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
    if err != nil {
        http.Error(w, "Conflict", http.StatusConflict)
        return fmt.Errorf("failed to create file %s: %s", absFilename, err)
    }
    defer targetFile.Close()

    writer := bufio.NewWriter(targetFile)
    _, err = io.Copy(writer, r.Body)
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return fmt.Errorf("failed to copy file contents to %s: %s", absFilename, err)
    }

    err = writer.Flush()
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return fmt.Errorf("failed to flush buffer to file %s: %s", absFilename, err)
    }

    uploadsTotal.Inc()
    w.WriteHeader(http.StatusCreated)
    return nil
}

// Handle resumable downloads
func handleResumableDownload(absFilename string, w http.ResponseWriter, r *http.Request) {
    rangeHeader := r.Header.Get("Range")
    if rangeHeader == "" {
        // If no Range header, serve the full file
        http.ServeFile(w, r, absFilename)
        return
    }

    // Parse Range header
    ranges := strings.Split(strings.TrimPrefix(rangeHeader, "bytes="), "-")
    if len(ranges) != 2 {
        http.Error(w, "Invalid Range", http.StatusRequestedRangeNotSatisfiable)
        return
    }

    start, err := strconv.ParseInt(ranges[0], 10, 64)
    if err != nil {
        http.Error(w, "Invalid Range", http.StatusRequestedRangeNotSatisfiable)
        return
    }

    fileInfo, err := os.Stat(absFilename)
    if err != nil {
        http.Error(w, "Not Found", http.StatusNotFound)
        return
    }

    // Calculate end byte
    end := fileInfo.Size() - 1
    if ranges[1] != "" {
        end, err = strconv.ParseInt(ranges[1], 10, 64)
        if err != nil || end > fileInfo.Size() {
            http.Error(w, "Invalid Range", http.StatusRequestedRangeNotSatisfiable)
            return
        }
    }

    // Set response headers for partial content
    w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, fileInfo.Size()))
    w.Header().Set("Content-Length", fmt.Sprintf("%d", end-start+1))
    w.WriteHeader(http.StatusPartialContent)

    // Serve the requested byte range
    file, err := os.Open(absFilename)
    if err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }
    defer file.Close()

    // Seek to the start byte
    _, err = file.Seek(start, 0)
    if err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    // Create a buffer and copy the specified range to the response writer
    buffer := make([]byte, end-start+1)
    _, err = io.ReadFull(file, buffer)
    if err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    w.Write(buffer)
}

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

    // Initialize the upload queue
    uploadQueue = make(chan UploadTask, UploadQueueSize)

    // Start the workers
    for i := 0; i < NumWorkers; i++ {
        go uploadWorker()
    }

    var proto string
    if conf.UnixSocket {
        proto = "unix"
    } else {
        proto = "tcp"
    }

    if conf.MetricsEnabled {
        prometheus.MustRegister(uploadDuration, uploadErrorsTotal, uploadsTotal)
        prometheus.MustRegister(downloadDuration, downloadsTotal, downloadErrorsTotal)
        prometheus.MustRegister(memoryUsage, cpuUsage, activeConnections, requestsTotal, goroutines)

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

    subpath := path.Join("/", conf.UploadSubDir)
    subpath = strings.TrimRight(subpath, "/") + "/"
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
        // Close the upload queue to signal workers to stop
        close(uploadQueue)
        // Optional: Wait for workers to finish
        time.Sleep(2 * time.Second)
        os.Exit(0)
    }()
}
