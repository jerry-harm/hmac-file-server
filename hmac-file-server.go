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
    "net/url"
    "os"
    "os/signal"
    "path"
    "path/filepath"
    "strconv"
    "strings"
    "syscall"

    "github.com/BurntSushi/toml"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/sirupsen/logrus"
    _ "net/http/pprof"
)

// Configuration struct
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
    RedisAddr              string
    RedisPassword          string
    RedisDB                int
    MetricsEnabled         bool
    MetricsPort            string
    ChunkSize              int
}

var conf Config
var log = logrus.New()

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

// Setup logging
func setupLogging() {
    if conf.LogFile != "" {
        file, err := os.OpenFile(conf.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
            log.Fatalf("Failed to open log file: %v", err)
        }
        writer := bufio.NewWriter(file)
        log.SetOutput(writer)
    } else {
        log.SetOutput(os.Stdout)
    }
    log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
}

// Handle request for uploads and downloads
func handleRequest(w http.ResponseWriter, r *http.Request) {
    log.Info("Incoming request: ", r.Method, r.URL.String())

    // Add CORS headers
    addCORSheaders(w)

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

// Handle uploads with HMAC validation
func handleUpload(w http.ResponseWriter, r *http.Request, absFilename string, fileStorePath string) {
    a, err := url.ParseQuery(r.URL.RawQuery)
    if err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    // Init HMAC
    mac := hmac.New(sha256.New, []byte(conf.Secret))
    mac.Write([]byte(fileStorePath + "\x20" + strconv.FormatInt(r.ContentLength, 10)))
    macString := hex.EncodeToString(mac.Sum(nil))

    if hmac.Equal([]byte(macString), []byte(a["v"][0])) {
        createFile(absFilename, w, r)
    } else {
        http.Error(w, "Forbidden", http.StatusForbidden)
    }
}

// Serve file for GET or HEAD requests
func serveFile(w http.ResponseWriter, r *http.Request, absFilename string) {
    fileInfo, err := os.Stat(absFilename)
    if err != nil {
        http.Error(w, "Not Found", http.StatusNotFound)
        return
    } else if fileInfo.IsDir() {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

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

// Create a new file during upload
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

// Set CORS headers
func addCORSheaders(w http.ResponseWriter) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
    w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
    w.Header().Set("Access-Control-Allow-Credentials", "true")
    w.Header().Set("Access-Control-Max-Age", "7200")
}

// Main function
func main() {
    var configFile string
    var proto string

    flag.StringVar(&configFile, "config", "./config.toml", "Path to configuration file.")
    flag.Parse()

    // Read config
    if err := readConfig(configFile, &conf); err != nil {
        log.Fatalln("Error reading config:", err)
    }

    setupLogging()

    if conf.UnixSocket {
        proto = "unix"
    } else {
        proto = "tcp"
    }

    listener, err := net.Listen(proto, conf.ListenPort)
    if err != nil {
        log.Fatalln("Could not open listener:", err)
    }

    // Start metrics server if enabled
    if conf.MetricsEnabled {
        go func() {
            http.Handle("/metrics", promhttp.Handler())
            log.Printf("Metrics server listening on %s", conf.MetricsPort)
            if err := http.ListenAndServe(conf.MetricsPort, nil); err != nil {
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
        log.Println("Shutting down server...")
        listener.Close()
        log.Println("Server stopped")
    }()

    log.Printf("Server started on %s. Waiting for requests.", conf.ListenPort)
    http.Serve(listener, nil)
}

// Read config from TOML
func readConfig(configFile string, config *Config) error {
    _, err := toml.DecodeFile(configFile, config)
    return err
}
