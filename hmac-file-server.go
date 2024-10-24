package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
)

// Configuration struct
type Config struct {
	ListenPort     string
	UnixSocket     bool
	StoreDir       string
	UploadSubDir   string
	LogLevel       string
	LogFile        string
	MetricsEnabled bool
	MetricsPort    string
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
	downloadDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "hmac",
		Name:      "file_server_download_duration_seconds",
		Help:      "Histogram of file download duration in seconds.",
		Buckets:   prometheus.DefBuckets,
	})
	downloadsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "hmac",
		Name:      "file_server_downloads_total",
		Help:      "Total number of successful file downloads.",
	})
	downloadErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "hmac",
		Name:      "file_server_download_errors_total",
		Help:      "Total number of file download errors.",
	})
	memoryUsage = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "hmac",
		Name:      "memory_usage_bytes",
		Help:      "Current memory usage in bytes.",
	})
	cpuUsage = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "hmac",
		Name:      "cpu_usage_percent",
		Help:      "Current CPU usage as a percentage.",
	})
	activeConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "hmac",
		Name:      "active_connections_total",
		Help:      "Total number of active connections.",
	})
	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "hmac",
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests received, labeled by method and path.",
		},
		[]string{"method", "path"},
	)
	goroutines = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "hmac",
		Name:      "goroutines_count",
		Help:      "Current number of goroutines.",
	})
)

func init() {
	prometheus.MustRegister(uploadDuration, uploadErrorsTotal, uploadsTotal)
	prometheus.MustRegister(downloadDuration, downloadsTotal, downloadErrorsTotal)
	prometheus.MustRegister(memoryUsage, cpuUsage, activeConnections, requestsTotal, goroutines)
}

// Log system information
func logSystemInfo() {
	log.Info("========================================")
	log.Info("         HMAC File Server               ")
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
	logSystemInfo() // Log system information at the start
}

// Request handler
func handleRequest(w http.ResponseWriter, r *http.Request) {
	log.Info("Incoming request: ", r.Method, r.URL.String())

	// Parse URL and args
	p := r.URL.Path
	subDir := path.Join("/", conf.UploadSubDir)
	fileStorePath := strings.TrimPrefix(p, subDir)
	if fileStorePath == "" || fileStorePath == "/" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	} else if fileStorePath[0] == '/' {
		fileStorePath = fileStorePath[1:]
	}

	absFilename := filepath.Join(conf.StoreDir, fileStorePath)
	addCORSheaders(w)

	if r.Method == http.MethodPut {
		startTime := time.Now() // Start timer for upload duration
		err := createFile(absFilename, w, r)
		if err != nil {
			log.Error(err)
			uploadErrorsTotal.Inc()
		} else {
			uploadsTotal.Inc()
			uploadDuration.Observe(time.Since(startTime).Seconds())
		}
	} else if r.Method == http.MethodGet || r.Method == http.MethodHead {
		serveFile(w, r, absFilename)
	} else if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, PUT, OPTIONS")
		return
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Serve file for GET or HEAD requests
func serveFile(w http.ResponseWriter, r *http.Request, absFilename string) {
	startTime := time.Now()

	fileInfo, err := os.Stat(absFilename)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		downloadErrorsTotal.Inc()
		return
	} else if fileInfo.IsDir() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		downloadErrorsTotal.Inc()
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

	downloadsTotal.Inc()
	downloadDuration.Observe(time.Since(startTime).Seconds())
}

// Add CORS headers
func addCORSheaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "7200")
}

// Create file during upload
func createFile(absFilename string, w http.ResponseWriter, r *http.Request) error {
	err := os.MkdirAll(filepath.Dir(absFilename), os.ModePerm)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return fmt.Errorf("failed to create directory %s: %s", absFilename, err)
	}

	targetFile, err := os.OpenFile(absFilename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		http.Error(w, "Conflict", http.StatusConflict)
		return fmt.Errorf("failed to create file %s: %s", absFilename, err)
	}
	defer targetFile.Close()

	_, err = io.Copy(targetFile, r.Body)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return fmt.Errorf("failed to copy file contents to %s: %s", absFilename, err)
	}

	w.WriteHeader(http.StatusCreated)
	return nil
}

// Main function
func main() {
	var configFile string

	flag.StringVar(&configFile, "config", "./config.toml", "Path to configuration file.")
	flag.Parse()

	if err := readConfig(configFile, &conf); err != nil {
		log.Fatalln("Error reading config:", err)
	}

	// Setup logging
	setupLogging()

	if conf.MetricsEnabled {
		go func() {
			http.Handle("/metrics", promhttp.Handler())
			if err := http.ListenAndServe(conf.MetricsPort, nil); err != nil {
				log.Fatalf("Metrics server failed: %v", err)
			}
		}()
	}

	var proto string
	if conf.UnixSocket {
		proto = "unix"
	} else {
		proto = "tcp"
	}

	listener, err := net.Listen(proto, conf.ListenPort)
	if err != nil {
		log.Fatalln("Could not open listening socket:", err)
	}

	subpath := path.Join("/", conf.UploadSubDir)
	subpath = strings.TrimRight(subpath, "/")
	subpath += "/"
	http.HandleFunc(subpath, handleRequest)

	log.Printf("Server started on port %s. Waiting for requests.\n", conf.ListenPort)
	err = http.Serve(listener, nil)
	if err != nil {
		log.Fatalf("HTTP server error: %v", err)
	}
}

// Read config from TOML
func readConfig(configFile string, config *Config) error {
	_, err := toml.DecodeFile(configFile, config)
	return err
}
