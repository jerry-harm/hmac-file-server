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
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	"github.com/sirupsen/logrus"
)

var conf Config
var versionString string = "v2.0"

var log = &logrus.Logger{
	Out:       os.Stdout,
	Formatter: new(logrus.TextFormatter),
	Hooks:     make(logrus.LevelHooks),
	Level:     logrus.DebugLevel,
}

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

// Configuration struct
type Config struct {
	ListenPort    string
	UnixSocket    bool
	Secret        string
	StoreDir      string
	UploadSubDir  string
	LogLevel      string
	MetricsEnabled bool
	MetricsPort    string
}

// Log system information with a banner
func logSystemInfo() {
	log.Info("========================================")
	log.Info("       HMAC File Server - v2.0          ")
	log.Info("  Secure File Handling with HMAC Auth   ")
	log.Info("========================================")

	log.Info("Features: Redis, Fallback Database (PostgreSQL/MySQL), Prometheus Metrics")
	log.Info("Build Date: 2024-10-23")

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

	// Get CPU information
	cpuInfo, _ := cpu.Info()
	for _, info := range cpuInfo {
		log.Infof("CPU Model: %s, Cores: %d, Mhz: %f", info.ModelName, info.Cores, info.Mhz)
	}

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

/*
 * Handles incoming HTTP requests, including HMAC validation and file uploads/downloads
 */
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
		/*
		 * User client tries to upload file
		 */

		/*
			Check if MAC is attached to URL and check protocol version.
			Ejabberd: supports "v" and probably "v2" - Prosody: supports "v" and "v2" - Metronome: supports: "token" (meaning "v2")
		*/
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

		// Calculate MAC, depending on protocolVersion
		if protocolVersion == "v" {
			// use a space character (0x20) between components of MAC
			mac.Write([]byte(fileStorePath + "\x20" + strconv.FormatInt(r.ContentLength, 10)))
			macString = hex.EncodeToString(mac.Sum(nil))
		} else if protocolVersion == "v2" || protocolVersion == "token" {
			// Get content type (for v2 / token)
			contentType := mime.TypeByExtension(filepath.Ext(fileStorePath))
			if contentType == "" {
				contentType = "application/octet-stream"
			}

			// use a null byte character (0x00) between components of MAC
			mac.Write([]byte(fileStorePath + "\x00" + strconv.FormatInt(r.ContentLength, 10) + "\x00" + contentType))
			macString = hex.EncodeToString(mac.Sum(nil))
		}

		/*
		 * Check whether calculated (expected) MAC is the MAC that client send in "v" URL parameter
		 */
		if hmac.Equal([]byte(macString), []byte(a[protocolVersion][0])) {
			err = createFile(absFilename, fileStorePath, w, r)
			if err != nil {
				log.Error(err)
			}
			return
		} else {
			log.Warning("Invalid MAC.")
			http.Error(w, "Invalid MAC", http.StatusForbidden)
			return
		}
	} else if r.Method == http.MethodHead || r.Method == http.MethodGet {
		/*
		 * User client tries to download a file
		 */

		fileInfo, err := os.Stat(absFilename)
		if err != nil {
			log.Error("Getting file information failed:", err)
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		} else if fileInfo.IsDir() {
			log.Warning("Directory listing forbidden!")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		/*
		 * Find out the content type to sent correct header. There is a Go function for retrieving the
		 * MIME content type, but this does not work with encrypted files (=> OMEMO). Therefore we're just
		 * relying on file extensions.
		 */
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
	} else if r.Method == http.MethodOptions {
		// Client CORS request: Return allowed methods
		w.Header().Set("Allow", "OPTIONS, GET, PUT, HEAD")
		return
	} else {
		// Client is using a prohibited / unsupported method
		log.Warn("Invalid method", r.Method, "for access to ", conf.UploadSubDir)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

// Create the file for upload
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
		http.Error(w, "Conflict", http.StatusConflict)
		return fmt.Errorf("failed to create file %s: %s", absFilename, err)
	}
	defer targetFile.Close()

	// Copy file contents to file
	_, err = io.Copy(targetFile, r.Body)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return fmt.Errorf("failed to copy file contents to %s: %s", absFilename, err)
	}

	uploadsTotal.Inc() // Increment successful upload counter
	w.WriteHeader(http.StatusCreated)
	return nil
}

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

func setLogLevel() {
	switch conf.LogLevel {
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

func main() {
	var configFile string
	var proto string

	// Parse command-line flags
	flag.StringVar(&configFile, "config", "./config.toml", "Path to configuration file \"config.toml\".")
	flag.Parse()

	if !flag.Parsed() {
		log.Fatalln("Could not parse flags")
	}

	// Read config file
	err := readConfig(configFile, &conf)
	if err != nil {
		log.Fatalln("There was an error while reading the configuration file:", err)
	}

	// Ensure that the HMAC StoreDir directory exists, create it if it does not
	err = os.MkdirAll(conf.StoreDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Could not create directory %s: %v", conf.StoreDir, err)
	}
	log.Infof("Directory %s is ready", conf.StoreDir)

	// Log system information
	logSystemInfo()

	// Select protocol
	if conf.UnixSocket {
		proto = "unix"
	} else {
		proto = "tcp"
	}

	// Register Prometheus metrics
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

	// Start the main server
	log.Println("Starting HMAC file server", versionString, "...")
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

	http.Serve(listener, nil)
}
