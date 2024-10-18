package main

import (
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
    "path"
    "path/filepath"
    "strconv"
    "strings"
    "github.com/BurntSushi/toml"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/sirupsen/logrus"
)

// Configuration of this server
type Config struct {
    ListenPort   string
    MetricsPort  string
    Secret       string
    StoreDir     string
    UploadSubDir string
    LogFile      string
}

var conf = Config{
    ListenPort:   ":8080",
    MetricsPort:  ":9090",
    StoreDir:     "/mnt/storage/hmac-file-server",
    UploadSubDir: "upload",
}

var log = logrus.New()

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

// Function to calculate the HMAC
func calculateHMAC(filePath string, contentLength int64, mimeType, protocolVersion string) string {
    mac := hmac.New(sha256.New, []byte(conf.Secret))
    var macString string

    if protocolVersion == "v" {
        mac.Write([]byte(filePath + "\x20" + strconv.FormatInt(contentLength, 10)))
    } else if protocolVersion == "v2" || protocolVersion == "token" {
        mac.Write([]byte(filePath + "\x00" + strconv.FormatInt(contentLength, 10) + "\x00" + mimeType))
    }

    macString = hex.EncodeToString(mac.Sum(nil))
    return macString
}

// Validate the HMAC and log the details
func validateHMAC(filePath string, contentLength int64, mimeType, protocolVersion, receivedHMAC string) bool {
    expectedHMAC := calculateHMAC(filePath, contentLength, mimeType, protocolVersion)

    // Log detailed information for debugging
    log.Infof("Expected HMAC: %s", expectedHMAC)
    log.Infof("Received HMAC: %s", receivedHMAC)
    log.Infof("File Path: %s", filePath)
    log.Infof("Content Length: %d", contentLength)
    log.Infof("MIME Type: %s", mimeType)
    log.Infof("Protocol Version: %s", protocolVersion)

    if hmac.Equal([]byte(expectedHMAC), []byte(receivedHMAC)) {
        log.Infof("HMAC validation successful for file: %s", filePath)
        return true
    }
    log.Warnf("HMAC validation failed for file: %s", filePath)
    return false
}

// Handle incoming requests, including HMAC verification
func handleRequest(w http.ResponseWriter, r *http.Request) {
    log.Infof("Handling %s request for path: %s", r.Method, r.URL.Path)

    // Parse query parameters
    a, err := url.ParseQuery(r.URL.RawQuery)
    if err != nil {
        log.Warn("Failed to parse query")
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

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

    // MIME type and content length
    mimeType := mime.TypeByExtension(filepath.Ext(r.URL.Path))
    if mimeType == "" {
        mimeType = "application/octet-stream"
    }

    // Content length can be 0 for chunked transfer encoding
    contentLength := r.ContentLength

    // Validate HMAC
    if !validateHMAC(r.URL.Path, contentLength, mimeType, protocolVersion, a[protocolVersion][0]) {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    // Handle file upload
    if r.Method == http.MethodPut {
        dirPath := path.Join(conf.StoreDir, r.URL.Path)
        if err := EnsureDirectoryExists(path.Dir(dirPath)); err != nil {
            log.Errorf("Failed to ensure directory exists: %s", path.Dir(dirPath), err)
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }

        file, err := os.OpenFile(dirPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
        if err != nil {
            log.Errorf("Error creating file: %s, error: %v", dirPath, err)
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }
        defer file.Close()

        // Read the file in chunks and write to disk
        buffer := make([]byte, 65536) // 64KB buffer
        for {
            n, err := r.Body.Read(buffer)
            if err != nil && err != io.EOF {
                log.Errorf("Error reading body: %v", err)
                http.Error(w, "Internal Server Error", http.StatusInternalServerError)
                return
            }
            if n == 0 {
                break
            }
            if _, err := file.Write(buffer[:n]); err != nil {
                log.Errorf("Error writing file: %v", err)
                http.Error(w, "Internal Server Error", http.StatusInternalServerError)
                return
            }
        }

        totalUploads.WithLabelValues("success").Inc()
        w.WriteHeader(http.StatusCreated)
        log.Infof("File successfully uploaded: %s", dirPath)
    } else {
        http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
    }
}

// Ensure the directory exists, or create it
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

// Setup logging to a file
func setupLogFile(logFile string) error {
    file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
    if err != nil {
        return err
    }
    log.SetOutput(file)
    return nil
}

func main() {
    var configFile string

    flag.StringVar(&configFile, "config", "./config.toml", "Path to configuration file \"config.toml\".")
    flag.Parse()

    // Read config file
    err := readConfig(configFile, &conf)
    if err != nil {
        log.Fatalln("Error reading configuration file:", err)
    }

    // Setup logging to file
    if err := setupLogFile(conf.LogFile); err != nil {
        log.Fatalf("Failed to set up log file: %v", err)
    }

    log.Println("Starting hmac-file-server...")

    listener, err := net.Listen("tcp", conf.ListenPort)
    if err != nil {
        log.Fatalln("Could not open listener:", err)
    }

    // Expose metrics if enabled
    go func() {
        log.Infof("Starting metrics server on port %s", conf.MetricsPort)
        http.Handle("/metrics", promhttp.Handler())
        if err := http.ListenAndServe(conf.MetricsPort, nil); err != nil {
            log.Fatalf("Metrics server failed: %s", err)
        }
    }()

    // Setup file upload handling
    subpath := path.Join("/", conf.UploadSubDir)
    subpath = strings.TrimRight(subpath, "/")
    subpath += "/"
    http.HandleFunc(subpath, handleRequest)

    log.Printf("Server started on port %s. Waiting for requests...\n", conf.ListenPort)

    if err := http.Serve(listener, nil); err != nil {
        log.Fatalln("Error serving HTTP server:", err)
    }
}

// Read the configuration file
func readConfig(configFile string, config *Config) error {
    _, err := toml.DecodeFile(configFile, config)
    return err
}