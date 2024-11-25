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
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/dutchcoders/go-clamd" // ClamAV integration
	"github.com/go-redis/redis/v8"    // Redis integration
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	"github.com/sirupsen/logrus"
)

// Configuration structure
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
	FileTTL                   string
	ResumableUploadsEnabled   bool
	ResumableDownloadsEnabled bool
	EnableVersioning          bool
	MaxVersions               int
	ChunkedUploadsEnabled     bool
	ChunkSize                 int64
	AllowedExtensions         []string

	// Server configuration Workers/QueueSize
	NumWorkers      int `toml:"NumWorkers"`
	UploadQueueSize int `toml:"UploadQueueSize"`

	// Server timeouts
	ReadTimeout  string
	WriteTimeout string
	IdleTimeout  string

	// ClamAV Configuration
	ClamAVSocket string `toml:"ClamAVSocket"` // ClamAV socket

	// Redis Configuration
	RedisEnabled             bool   `toml:"RedisEnabled"` // Enable/disable Redis
	RedisDBIndex             int    `toml:"RedisDBIndex"`
	RedisAddr                string `toml:"RedisAddr"`
	RedisPassword            string `toml:"RedisPassword"`
	RedisHealthCheckInterval string `toml:"RedisHealthCheckInterval"` // e.g., "30s"

	// Graceful Shutdown timeout
	GracefulShutdownTimeout int `toml:"GracefulShutdownTimeout"`

	// IP Management settings
	EnableIPManagement bool     `toml:"EnableIPManagement"` // Enable IP management
	AllowedIPs         []string `toml:"AllowedIPs"`         // Whitelist of allowed IPs
	BlockedIPs         []string `toml:"BlockedIPs"`         // Blacklist of blocked IPs
	IPCheckInterval    string   `toml:"IPCheckInterval"`    // Interval for IP check updates

	// Rate Limiting settings
	EnableRateLimiting bool   `toml:"EnableRateLimiting"` // Enable rate limiting
	RequestsPerMinute  int    `toml:"RequestsPerMinute"`  // Allowed requests per minute per IP
	RateLimitInterval  string `toml:"RateLimitInterval"`  // Rate limit interval (e.g., "1m")

	// Fail2Ban settings
	Fail2BanEnabled bool   `toml:"Fail2BanEnabled"` // Enable Fail2Ban
	Fail2BanCommand string `toml:"Fail2BanCommand"` // Path to the Fail2Ban command
	Fail2BanJail    string `toml:"Fail2BanJail"`    // Jail name for Fail2Ban

	// Deduplication settings
	DeduplicationEnabled bool `toml:"DeduplicationEnabled"` // Enable deduplication based on checksum
}

// UploadTask represents a file upload task
type UploadTask struct {
	AbsFilename string
	Request     *http.Request
	Result      chan error
}

// ScanTask represents a file scan task
type ScanTask struct {
	AbsFilename string
	Result      chan error
}

// NetworkEvent represents a network-related event
type NetworkEvent struct {
	Type    string
	Details string
}

var (
	conf          Config
	versionString string = "v2.0.5"
	log                  = logrus.New()
	uploadQueue   chan UploadTask
	networkEvents chan NetworkEvent
	fileInfoCache *cache.Cache

	// Prometheus metrics
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
	requestsTotalCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "hmac",
		Name:      "http_requests_total",
		Help:      "Total number of HTTP requests received, labeled by method and path.",
	}, []string{"method", "path"})
	goroutines = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "hmac",
		Name:      "goroutines_count",
		Help:      "Current number of goroutines.",
	})
	uploadSizeBytes = prometheus.NewHistogram(prometheus.HistogramOpts{
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
	infectedFilesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "hmac",
		Name:      "infected_files_total",
		Help:      "Total number of infected files detected.",
	})
	deletedFilesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "hmac",
		Name:      "file_deletions_total",
		Help:      "Total number of files deleted based on FileTTL.",
	})

	// ClamAV client
	clamClient *clamd.Clamd // ClamAV client

	// Redis Client
	redisClient *redis.Client // Redis client

	// Channels
	scanQueue   chan ScanTask
	ScanWorkers = 5 // Number of ClamAV scan workers

	// Redis connection status
	redisConnected bool = false
	mu             sync.RWMutex

	// Rate Limiting data structures
	requestCounters     *cache.Cache
	rateLimitInterval   time.Duration
	requestsPerInterval int
)

const defaultRateLimitInterval = "1m"

// Function to parse duration strings with h (hours), d (days), and y (years).
func ParseCustomDuration(s string) (time.Duration, error) {
	var totalDuration time.Duration
	var number string
	for i, char := range s {
		if char >= '0' && char <= '9' {
			number += string(char)
			continue
		}
		if char == 'h' || char == 'd' || char == 'y' || char == 'm' {
			if number == "" {
				return 0, fmt.Errorf("invalid duration format at position %d", i)
			}
			value, err := strconv.Atoi(number)
			if err != nil {
				return 0, fmt.Errorf("invalid number %s in duration", number)
			}
			switch char {
			case 'h':
				totalDuration += time.Duration(value) * time.Hour
			case 'd':
				totalDuration += time.Duration(value) * 24 * time.Hour
			case 'y':
				totalDuration += time.Duration(value) * 365 * 24 * time.Hour
			case 'm':
				totalDuration += time.Duration(value) * time.Minute
			}
			number = ""
		} else {
			return 0, fmt.Errorf("invalid duration unit '%c' in duration", char)
		}
	}
	if number != "" {
		return 0, fmt.Errorf("invalid duration format, trailing number %s without unit", number)
	}
	return totalDuration, nil
}

// Initialize Prometheus metrics
func initMetrics() {
	if conf.MetricsEnabled {
		prometheus.MustRegister(uploadDuration)
		prometheus.MustRegister(uploadErrorsTotal)
		prometheus.MustRegister(uploadsTotal)
		prometheus.MustRegister(downloadDuration)
		prometheus.MustRegister(downloadsTotal)
		prometheus.MustRegister(downloadErrorsTotal)
		prometheus.MustRegister(memoryUsage)
		prometheus.MustRegister(cpuUsage)
		prometheus.MustRegister(requestsTotalCounter)
		prometheus.MustRegister(goroutines)
		prometheus.MustRegister(uploadSizeBytes)
		prometheus.MustRegister(downloadSizeBytes)
		prometheus.MustRegister(infectedFilesTotal)
		prometheus.MustRegister(deletedFilesTotal)
	}
}

// Initialize Redis client
func initRedis() {
	if !conf.RedisEnabled {
		log.Info("Redis is disabled in configuration.")
		return
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr:     conf.RedisAddr,
		Password: conf.RedisPassword,
		DB:       conf.RedisDBIndex,
	})

	// Test the Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	log.Info("Connected to Redis successfully")

	// Set initial connection status
	mu.Lock()
	redisConnected = true
	mu.Unlock()
}

// Block an IP using Fail2Ban
func blockIPFail2Ban(ip string) error {
	if conf.Fail2BanEnabled {
		cmd := exec.Command(conf.Fail2BanCommand, "set", conf.Fail2BanJail, "ban", ip)
		if err := cmd.Run(); err != nil {
			log.Errorf("Failed to block IP %s with Fail2Ban: %v", ip, err)
			return err
		}
		log.Infof("Blocked IP %s using Fail2Ban", ip)
	}
	return nil
}

func main() {
	// Flags for configuration file
	var configFile string
	flag.StringVar(&configFile, "config", "./config.toml", "Path to configuration file \"config.toml\".")
	flag.Parse()

	// Load configuration
	err := readConfig(configFile, &conf)
	if err != nil {
		log.Fatalln("Error reading configuration file:", err)
	}

	// Initialize Redis client if enabled
	if conf.RedisEnabled {
		initRedis()
	}

	// Initialize metrics
	initMetrics()

	// Initialize file info cache
	fileInfoCache = cache.New(5*time.Minute, 10*time.Minute)

	// Initialize request counters for rate limiting
	if conf.EnableRateLimiting {
		interval := conf.RateLimitInterval
		if interval == "" {
			interval = defaultRateLimitInterval
		}
		rateLimitInterval, err = ParseCustomDuration(interval)
		if err != nil {
			log.Fatalf("Invalid RateLimitInterval value: %v", err)
		}
		requestsPerInterval = conf.RequestsPerMinute
		requestCounters = cache.New(rateLimitInterval, 2*rateLimitInterval)
	}

	// Create store directory
	err = os.MkdirAll(conf.StoreDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Could not create directory %s: %v", conf.StoreDir, err)
	}
	log.WithField("directory", conf.StoreDir).Info("Store directory is ready")

	// Setup logging
	setupLogging()

	// Log system information
	logSystemInfo()

	// Initialize upload and scan queues
	uploadQueue = make(chan UploadTask, conf.UploadQueueSize)
	scanQueue = make(chan ScanTask, conf.UploadQueueSize)
	networkEvents = make(chan NetworkEvent, 100)

	// Context for goroutines
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start network monitoring and system metrics updates
	go monitorNetwork(ctx)
	go handleNetworkEvents(ctx)
	go updateSystemMetrics(ctx)

	// Initialize ClamAV client
	clamClient, err = initClamAV(conf.ClamAVSocket)
	if err != nil {
		log.WithError(err).Warn("ClamAV client initialization failed. Continuing without ClamAV.")
	} else {
		log.Info("ClamAV client initialized successfully")
	}

	// Initialize worker pools
	initializeUploadWorkerPool(ctx)
	if clamClient != nil {
		initializeScanWorkerPool(ctx)
	}

	// Parse FileTTL
	fileTTLDuration, err := ParseCustomDuration(conf.FileTTL)
	if err != nil {
		log.Fatalf("Invalid FileTTL value: %v", err)
	}
	log.Infof("FileTTL set to %v", fileTTLDuration)

	// Start file cleanup routine
	go startFileCleanup(ctx, conf.StoreDir, fileTTLDuration)

	// Start Redis health monitor if Redis is enabled
	if conf.RedisEnabled && redisClient != nil {
		go MonitorRedisHealth(ctx, redisClient, parseHealthCheckInterval(conf.RedisHealthCheckInterval))
	}

	// Setup router
	router := setupRouter()

	// Parse timeout durations
	readTimeout, err := time.ParseDuration(conf.ReadTimeout)
	if err != nil {
		log.Fatalf("Invalid ReadTimeout value: %v", err)
	}

	writeTimeout, err := time.ParseDuration(conf.WriteTimeout)
	if err != nil {
		log.Fatalf("Invalid WriteTimeout value: %v", err)
	}

	idleTimeout, err := time.ParseDuration(conf.IdleTimeout)
	if err != nil {
		log.Fatalf("Invalid IdleTimeout value: %v", err)
	}

	// Configure HTTP server
	server := &http.Server{
		Addr:         conf.ListenPort,
		Handler:      router,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
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

// Function to load configuration file
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

	// Set default values for optional settings
	if conf.MaxVersions == 0 {
		conf.MaxVersions = 0 // Default: no maximum number of versions
	}
	if conf.ChunkSize == 0 {
		conf.ChunkSize = 1048576 // Default chunk size: 1MB
	}
	if conf.AllowedExtensions == nil {
		conf.AllowedExtensions = []string{} // Default: no restrictions
	}

	// Set default values for server timeouts if they are not set
	if conf.ReadTimeout == "" {
		conf.ReadTimeout = "2h" // Default read timeout
	}
	if conf.WriteTimeout == "" {
		conf.WriteTimeout = "2h" // Default write timeout
	}
	if conf.IdleTimeout == "" {
		conf.IdleTimeout = "2h" // Default idle timeout
	}

	// Set default FileTTL if not set
	if conf.FileTTL == "" {
		conf.FileTTL = "7d" // Default FileTTL: 7 days
	}

	// Ensure RedisDBIndex is set; default to 0 if not provided
	if conf.RedisDBIndex == 0 && conf.RedisEnabled {
		conf.RedisDBIndex = 0 // Default Redis DB
	}

	// Set default RedisHealthCheckInterval if not set
	if conf.RedisHealthCheckInterval == "" && conf.RedisEnabled {
		conf.RedisHealthCheckInterval = "30s" // Default health check interval
	}

	// Set default IPCheckInterval if not set
	if conf.IPCheckInterval == "" && conf.EnableIPManagement {
		conf.IPCheckInterval = "60s" // Default IP check interval
	}

	// Set default RateLimitInterval if not set
	if conf.RateLimitInterval == "" && conf.EnableRateLimiting {
		conf.RateLimitInterval = defaultRateLimitInterval
	}

	// Set default DeduplicationEnabled if not set
	// (default is false due to zero-value of bool)
	return nil
}

// Parse health check interval from config
func parseHealthCheckInterval(intervalStr string) time.Duration {
	dur, err := time.ParseDuration(intervalStr)
	if err != nil {
		log.Warnf("Invalid interval '%s', defaulting to 30s", intervalStr)
		return 30 * time.Second
	}
	return dur
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

	// Use JSON formatter for structured logging
	log.SetFormatter(&logrus.JSONFormatter{})
}

// Log system information
func logSystemInfo() {
	log.Info("========================================")
	log.Infof("       HMAC File Server - %s          ", versionString)
	log.Info("  Secure File Handling with HMAC Auth   ")
	log.Info("========================================")

	log.Info("Features: Prometheus Metrics, Chunked Uploads, ClamAV Scanning, Deduplication")
	log.Info("Build Date: 2024-10-28")

	log.Infof("Operating System: %s", runtime.GOOS)
	log.Infof("Architecture: %s", runtime.GOARCH)
	log.Infof("Number of CPUs: %d", runtime.NumCPU())
	log.Infof("Go Version: %s", runtime.Version())

	// Always log system information
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

// Function to check if a file exists and return its size
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

// Function to check file extension
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

// Version the file by moving the existing file to a versioned directory
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
		"original":      absFilename,
		"versioned_as":  versionedFilename,
		"version_dir":   versionDir,
		"version_count": conf.MaxVersions,
	}).Info("Versioned old file")
	return cleanupOldVersions(versionDir)
}

// Clean up older versions if they exceed the maximum allowed
func cleanupOldVersions(versionDir string) error {
	files, err := os.ReadDir(versionDir)
	if err != nil {
		return fmt.Errorf("failed to list version files: %v", err)
	}

	if conf.MaxVersions > 0 && len(files) > conf.MaxVersions {
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

// CalculateChecksum calculates the SHA-256 checksum of a given file
func CalculateChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to calculate checksum: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Process the upload task with deduplication
func processUpload(task UploadTask) error {
	absFilename := task.AbsFilename
	tempFilename := absFilename + ".tmp"
	r := task.Request

	startTime := time.Now()

	// Handle uploads and write to a temporary file
	if conf.ChunkedUploadsEnabled {
		err := handleChunkedUpload(tempFilename, r)
		if err != nil {
			uploadDuration.Observe(time.Since(startTime).Seconds())
			log.WithFields(logrus.Fields{
				"file":  tempFilename,
				"error": err,
			}).Error("Failed to handle chunked upload")
			return err
		}
	} else {
		err := createFile(tempFilename, r)
		if err != nil {
			log.WithFields(logrus.Fields{
				"file":  tempFilename,
				"error": err,
			}).Error("Error creating file")
			uploadDuration.Observe(time.Since(startTime).Seconds())
			return err
		}
	}

	// Perform ClamAV scan on the temporary file
	if clamClient != nil {
		err := scanFileWithClamAV(tempFilename)
		if err != nil {
			log.WithFields(logrus.Fields{
				"file":  tempFilename,
				"error": err,
			}).Warn("ClamAV detected a virus or scan failed")
			os.Remove(tempFilename)
			uploadErrorsTotal.Inc()
			return err
		}
	}

	// Deduplication logic
	if conf.DeduplicationEnabled && conf.RedisEnabled && redisConnected && redisClient != nil {
		// Calculate checksum
		checksum, err := CalculateChecksum(tempFilename)
		if err != nil {
			log.WithError(err).Error("Failed to calculate checksum for deduplication")
			os.Remove(tempFilename)
			uploadErrorsTotal.Inc()
			return err
		}

		checksumKey := fmt.Sprintf("checksum:%s", checksum)
		filenameKey := fmt.Sprintf("filename:%s", filepath.Base(absFilename))

		// Check if checksum exists
		exists, err := redisClient.Exists(context.Background(), checksumKey).Result()
		if err != nil {
			log.WithError(err).Error("Failed to check checksum in Redis")
			os.Remove(tempFilename)
			uploadErrorsTotal.Inc()
			return err
		}

		if exists > 0 {
			// Duplicate found, map filename to existing checksum and remove temp file
			err = redisClient.SAdd(context.Background(), checksumKey, filepath.Base(absFilename)).Err()
			if err != nil {
				log.WithError(err).Error("Failed to add filename to checksum set in Redis")
				os.Remove(tempFilename)
				uploadErrorsTotal.Inc()
				return err
			}

			err = redisClient.Set(context.Background(), filenameKey, checksum, 0).Err()
			if err != nil {
				log.WithError(err).Error("Failed to map filename to checksum in Redis")
				os.Remove(tempFilename)
				uploadErrorsTotal.Inc()
				return err
			}

			// Remove the temporary file as it's a duplicate
			err = os.Remove(tempFilename)
			if err != nil {
				log.WithError(err).Error("Failed to remove duplicate temporary file")
				uploadErrorsTotal.Inc()
				return err
			}

			log.WithFields(logrus.Fields{
				"file":      absFilename,
				"checksum":  checksum,
				"duplicate": true,
			}).Info("Duplicate file detected. Mapped filename to existing checksum.")
			uploadDuration.Observe(time.Since(startTime).Seconds())
			uploadsTotal.Inc()
			return nil
		} else {
			// Unique file, rename temp file to checksum filename and map filename to checksum
			checksumFilename := checksum
			finalPath := filepath.Join(conf.StoreDir, checksumFilename)
			err = os.Rename(tempFilename, finalPath)
			if err != nil {
				log.WithError(err).Error("Failed to rename temporary file to checksum filename")
				os.Remove(tempFilename)
				uploadErrorsTotal.Inc()
				return err
			}

			// Add filename to checksum set and map filename to checksum
			err = redisClient.SAdd(context.Background(), checksumKey, filepath.Base(absFilename)).Err()
			if err != nil {
				log.WithError(err).Error("Failed to add filename to checksum set in Redis")
				return err
			}

			err = redisClient.Set(context.Background(), filenameKey, checksum, 0).Err()
			if err != nil {
				log.WithError(err).Error("Failed to map filename to checksum in Redis")
				return err
			}

			log.WithFields(logrus.Fields{
				"file":     absFilename,
				"checksum": checksum,
			}).Info("Unique file uploaded and stored with checksum.")
			uploadDuration.Observe(time.Since(startTime).Seconds())
			uploadsTotal.Inc()
			return nil
		}
	}

	// Handle file versioning if enabled
	if conf.EnableVersioning {
		existing, _ := fileExists(absFilename)
		if existing {
			err := versionFile(absFilename)
			if err != nil {
				log.WithFields(logrus.Fields{
					"file":  absFilename,
					"error": err,
				}).Error("Error versioning file")
				os.Remove(tempFilename)
				return err
			}
		}
	}

	// Removed duplicate function definition

	log.WithFields(logrus.Fields{
		"file": absFilename,
	}).Info("File uploaded and scanned successfully")

	uploadDuration.Observe(time.Since(startTime).Seconds())
	uploadsTotal.Inc()
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
			log.WithFields(logrus.Fields{
				"worker_id": workerID,
				"file":      task.AbsFilename,
			}).Info("Processing upload task")
			err := processUpload(task)
			if err != nil {
				log.WithFields(logrus.Fields{
					"worker_id": workerID,
					"file":      task.AbsFilename,
					"error":     err,
				}).Error("Failed to process upload task")
				uploadErrorsTotal.Inc()
				blockIPFail2Ban(getClientIP(task.Request)) // Block IP after failed uploads
			} else {
				log.WithFields(logrus.Fields{
					"worker_id": workerID,
					"file":      task.AbsFilename,
				}).Info("Successfully processed upload task")
			}
			task.Result <- err
			close(task.Result)
		}
	}
}

// Initialize upload worker pool
func initializeUploadWorkerPool(ctx context.Context) {
	for i := 0; i < conf.NumWorkers; i++ {
		go uploadWorker(ctx, i)
	}
	log.Infof("Initialized %d upload workers", conf.NumWorkers)
}

// Worker function to process scan tasks
func scanWorker(ctx context.Context, workerID int) {
	log.WithField("worker_id", workerID).Info("Scan worker started")
	for {
		select {
		case <-ctx.Done():
			log.WithField("worker_id", workerID).Info("Scan worker stopping")
			return
		case task, ok := <-scanQueue:
			if !ok {
				log.WithField("worker_id", workerID).Info("Scan queue closed")
				return
			}
			log.WithFields(logrus.Fields{
				"worker_id": workerID,
				"file":      task.AbsFilename,
			}).Info("Processing scan task")
			err := scanFileWithClamAV(task.AbsFilename)
			if err != nil {
				log.WithFields(logrus.Fields{
					"worker_id": workerID,
					"file":      task.AbsFilename,
					"error":     err,
				}).Error("Failed to scan file")
			} else {
				log.WithFields(logrus.Fields{
					"worker_id": workerID,
					"file":      task.AbsFilename,
				}).Info("Successfully scanned file")
			}
			task.Result <- err
			close(task.Result)
		}
	}
}

// Initialize scan worker pool
func initializeScanWorkerPool(ctx context.Context) {
	for i := 0; i < ScanWorkers; i++ {
		go scanWorker(ctx, i)
	}
	log.Infof("Initialized %d scan workers", ScanWorkers)
}

// Setup router with middleware
func setupRouter() http.Handler {
	mux := http.NewServeMux()

	// Handle upload and download requests
	subpath := path.Join("/", conf.UploadSubDir)
	subpath = strings.TrimRight(subpath, "/") + "/"
	mux.HandleFunc(subpath, handleRequest)

	// Handle example Redis usage
	mux.HandleFunc("/example", exampleRedisUsage)

	if conf.MetricsEnabled {
		mux.Handle("/metrics", promhttp.Handler())
	}

	// Apply middleware
	handler := loggingMiddleware(mux)
	handler = recoveryMiddleware(handler)
	return handler
}

// Middleware for logging
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestsTotalCounter.WithLabelValues(r.Method, r.URL.Path).Inc()
		next.ServeHTTP(w, r)
	})
}

// Middleware for panic recovery
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.WithFields(logrus.Fields{
					"method": r.Method,
					"url":    r.URL.String(),
					"error":  rec,
				}).Error("Panic recovered in HTTP handler")
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Extract client IP considering proxy headers
func getClientIP(r *http.Request) string {
	// Attempt to get the real client IP from headers
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.Header.Get("X-Real-IP")
	}
	if clientIP == "" {
		// Fallback to RemoteAddr if no headers are present
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.WithError(err).Warn("Failed to parse RemoteAddr")
			clientIP = r.RemoteAddr
		} else {
			clientIP = host
		}
	} else {
		// If there are multiple IPs in X-Forwarded-For, take the first one
		clientIP = strings.Split(clientIP, ",")[0]
	}

	return strings.TrimSpace(clientIP)
}

// Check if IP is allowed based on AllowedIPs and BlockedIPs
func isIPAllowed(clientIP string) bool {
	// Check against blocked IPs
	for _, blockedIP := range conf.BlockedIPs {
		if clientIP == blockedIP {
			return false // Blocked IP
		}
	}

	// Check against allowed IPs
	if len(conf.AllowedIPs) > 0 {
		for _, allowedIP := range conf.AllowedIPs {
			if clientIP == allowedIP {
				return true // Allowed IP
			}
		}
		return false // Not in allowed IPs
	}

	return true // No restrictions
}

// Rate limiting based on client IP
func isRateLimited(clientIP string) bool {
	if !conf.EnableRateLimiting {
		return false
	}

	count, found := requestCounters.Get(clientIP)
	if !found {
		requestCounters.Set(clientIP, 1, rateLimitInterval)
		return false
	}

	requestCount := count.(int)
	if requestCount >= requestsPerInterval {
		return true
	}

	requestCounters.Increment(clientIP, 1)
	return false
}

// Handle file uploads and downloads
func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Get client IP address
	clientIP := getClientIP(r)

	// Log the request with the client IP
	log.WithFields(logrus.Fields{
		"method":    r.Method,
		"url":       r.URL.String(),
		"client_ip": clientIP,
	}).Info("Incoming request")

	// Check if IP is allowed
	if conf.EnableIPManagement && !isIPAllowed(clientIP) {
		log.WithField("client_ip", clientIP).Warn("Unauthorized IP address")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Check rate limiting
	if isRateLimited(clientIP) {
		log.WithField("client_ip", clientIP).Warn("Rate limit exceeded")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// Parse URL and query parameters
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

	// Decode the fileStorePath to handle URL-encoded paths
	fileStorePath, err = url.PathUnescape(fileStorePath)
	if err != nil {
		log.Warn("Failed to decode file path")
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}

	absFilename := filepath.Join(conf.StoreDir, fileStorePath)

	// Prevent path traversal by ensuring absFilename is within conf.StoreDir
	absStoreDir, err := filepath.Abs(conf.StoreDir)
	if err != nil {
		log.Error("Failed to get absolute path of store directory")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	absFilename, err = filepath.Abs(absFilename)
	if err != nil || !strings.HasPrefix(absFilename, absStoreDir) {
		log.Warn("Attempted path traversal attack: ", absFilename)
		http.Error(w, "Forbidden", http.StatusForbidden)
		downloadErrorsTotal.Inc()
		return
	}

	switch r.Method {
	case http.MethodPut:
		handleUpload(w, r, absFilename, fileStorePath, a)
	case http.MethodHead, http.MethodGet:
		handleDownload(w, r, absFilename, fileStorePath)
	case http.MethodOptions:
		// Handled by NGINX; no action needed
		w.Header().Set("Allow", "OPTIONS, GET, PUT, HEAD")
		return
	default:
		log.WithField("method", r.Method).Warn("Invalid HTTP method for upload directory")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
}

// Handle file uploads with extension restrictions, HMAC validation, and deduplication
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
	log.Debugf("Protocol version determined: %s", protocolVersion)

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
	log.Debugf("Calculated MAC: %x", calculatedMAC)

	// Decode provided MAC from hex
	providedMACHex := a.Get(protocolVersion)
	providedMAC, err := hex.DecodeString(providedMACHex)
	if err != nil {
		log.Warn("Invalid MAC encoding")
		http.Error(w, "Invalid MAC encoding", http.StatusForbidden)
		return
	}
	log.Debugf("Provided MAC: %x", providedMAC)

	// Validate the HMAC
	if !hmac.Equal(calculatedMAC, providedMAC) {
		log.Warn("Invalid MAC")
		http.Error(w, "Invalid MAC", http.StatusForbidden)
		return
	}
	log.Debug("HMAC validation successful")

	// Store HMAC Token in Redis if protocolVersion is "token"
	if protocolVersion == "token" {
		mu.RLock()
		connected := redisConnected
		mu.RUnlock()

		if conf.RedisEnabled && connected && redisClient != nil {
			token := a.Get("token")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Set token with an expiration time
			err := redisClient.Set(ctx, token, "valid", 24*time.Hour).Err()
			if err != nil {
				log.WithError(err).Error("Failed to store HMAC token in Redis")
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			log.Info("HMAC token stored in Redis successfully")
		} else {
			log.Warn("Cannot store HMAC token in Redis: Redis is not connected")
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
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

	// Create an UploadTask with a result channel
	result := make(chan error)
	task := UploadTask{
		AbsFilename: absFilename,
		Request:     r,
		Result:      result,
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
	err = <-result
	if err != nil {
		// The worker has already logged the error; send an appropriate HTTP response
		http.Error(w, fmt.Sprintf("Upload failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Retrieve and delete HMAC Token from Redis after Successful Upload
	if protocolVersion == "token" {
		mu.RLock()
		connected := redisConnected
		mu.RUnlock()

		if conf.RedisEnabled && connected && redisClient != nil {
			token := a.Get("token")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Delete the token after use
			err := redisClient.Del(ctx, token).Err()
			if err != nil {
				log.WithError(err).Error("Failed to delete HMAC token from Redis")
			}
			log.Info("HMAC token deleted from Redis successfully")
		} else {
			log.Warn("Cannot delete HMAC token from Redis: Redis is not connected")
		}
	}

	// Upload was successful
	w.WriteHeader(http.StatusCreated)
}

// Handle file downloads with deduplication
func handleDownload(w http.ResponseWriter, r *http.Request, absFilename, fileStorePath string) {
	var actualFilePath string
	var fileInfo os.FileInfo
	var err error

	if conf.DeduplicationEnabled && conf.RedisEnabled && redisConnected && redisClient != nil {
		// Map filename to checksum
		filenameKey := fmt.Sprintf("filename:%s", filepath.Base(absFilename))
		checksum, err := redisClient.Get(context.Background(), filenameKey).Result()
		if err != nil {
			if err == redis.Nil {
				log.WithField("filename", filepath.Base(absFilename)).Warn("Filename not found in Redis")
				http.Error(w, "Not Found", http.StatusNotFound)
				downloadErrorsTotal.Inc()
				return
			}
			log.WithError(err).Error("Failed to retrieve checksum from Redis")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			downloadErrorsTotal.Inc()
			return
		}

		// Construct the actual file path using checksum
		actualFilePath = filepath.Join(conf.StoreDir, checksum)

		// Check if the actual file exists
		fileInfo, err = getFileInfo(actualFilePath)
		if err != nil {
			log.WithFields(logrus.Fields{
				"file":  actualFilePath,
				"error": err,
			}).Error("Failed to get file information for checksum file")
			http.Error(w, "Not Found", http.StatusNotFound)
			downloadErrorsTotal.Inc()
			return
		} else if fileInfo.IsDir() {
			log.Warn("Directory listing forbidden for checksum file")
			http.Error(w, "Forbidden", http.StatusForbidden)
			downloadErrorsTotal.Inc()
			return
		}
	} else {
		// Standard download without deduplication
		fileInfo, err = getFileInfo(absFilename)
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
		actualFilePath = absFilename
	}

	contentType := mime.TypeByExtension(filepath.Ext(fileStorePath))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)

	// Handle resumable downloads
	if conf.ResumableDownloadsEnabled {
		handleResumableDownload(actualFilePath, w, r, fileInfo.Size())
		return
	}

	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))
		downloadsTotal.Inc()
		return
	} else {
		// Measure download duration
		startTime := time.Now()
		http.ServeFile(w, r, actualFilePath)
		downloadDuration.Observe(time.Since(startTime).Seconds())
		downloadSizeBytes.Observe(float64(fileInfo.Size()))
		downloadsTotal.Inc()
		return
	}
}

// Create the file for upload with buffered Writer
func createFile(tempFilename string, r *http.Request) error {
	absDirectory := filepath.Dir(tempFilename)
	err := os.MkdirAll(absDirectory, os.ModePerm)
	if err != nil {
		log.WithError(err).Errorf("Failed to create directory %s", absDirectory)
		return fmt.Errorf("failed to create directory %s: %w", absDirectory, err)
	}

	// Open the file for writing
	targetFile, err := os.OpenFile(tempFilename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.WithError(err).Errorf("Failed to create file %s", tempFilename)
		return fmt.Errorf("failed to create file %s: %w", tempFilename, err)
	}
	defer targetFile.Close()

	// Use a large buffer for efficient file writing
	bufferSize := 4 * 1024 * 1024 // 4 MB buffer
	writer := bufio.NewWriterSize(targetFile, bufferSize)
	buffer := make([]byte, bufferSize)

	totalBytes := int64(0)
	for {
		n, readErr := r.Body.Read(buffer)
		if n > 0 {
			totalBytes += int64(n)
			_, writeErr := writer.Write(buffer[:n])
			if writeErr != nil {
				log.WithError(writeErr).Errorf("Failed to write to file %s", tempFilename)
				return fmt.Errorf("failed to write to file %s: %w", tempFilename, writeErr)
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			log.WithError(readErr).Error("Failed to read request body")
			return fmt.Errorf("failed to read request body: %w", readErr)
		}
	}

	err = writer.Flush()
	if err != nil {
		log.WithError(err).Errorf("Failed to flush buffer to file %s", tempFilename)
		return fmt.Errorf("failed to flush buffer to file %s: %w", tempFilename, err)
	}

	log.WithFields(logrus.Fields{
		"temp_file":   tempFilename,
		"total_bytes": totalBytes,
	}).Info("File uploaded successfully")

	uploadSizeBytes.Observe(float64(totalBytes))
	return nil
}

// Scan the uploaded file with ClamAV
func scanFileWithClamAV(filePath string) error {
	log.WithField("file", filePath).Info("Scanning file with ClamAV")

	scanResultChan, err := clamClient.ScanFile(filePath)
	if err != nil {
		log.WithError(err).Error("Failed to initiate ClamAV scan")
		return fmt.Errorf("failed to initiate ClamAV scan: %w", err)
	}

	// Receive scan result
	scanResult := <-scanResultChan
	if scanResult == nil {
		log.Error("Failed to receive scan result from ClamAV")
		return fmt.Errorf("failed to receive scan result from ClamAV")
	}

	// Handle scan result
	switch scanResult.Status {
	case clamd.RES_OK:
		log.WithField("file", filePath).Info("ClamAV scan passed")
		return nil
	case clamd.RES_FOUND:
		log.WithFields(logrus.Fields{
			"file":        filePath,
			"description": scanResult.Description,
		}).Warn("ClamAV detected a virus")
		infectedFilesTotal.Inc()
		return fmt.Errorf("virus detected: %s", scanResult.Description)
	default:
		log.WithFields(logrus.Fields{
			"file":        filePath,
			"status":      scanResult.Status,
			"description": scanResult.Description,
		}).Warn("ClamAV scan returned unexpected status")
		return fmt.Errorf("ClamAV scan returned unexpected status: %s", scanResult.Description)
	}
}

// Initialize ClamAV client
func initClamAV(socket string) (*clamd.Clamd, error) {
	client := clamd.NewClamd(socket)
	if client == nil {
		return nil, fmt.Errorf("failed to create ClamAV client for socket: %s", socket)
	}

	// Ping ClamAV to verify connection
	err := client.Ping()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ClamAV: %w", err)
	}

	return client, nil
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

	// Reject multiple ranges
	if strings.Contains(rangeHeader, ",") {
		http.Error(w, "Multiple ranges not supported", http.StatusRequestedRangeNotSatisfiable)
		downloadErrorsTotal.Inc()
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
		if err != nil || end >= fileSize || start > end {
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

// Handle chunked uploads with bufio.Writer
func handleChunkedUpload(tempFilename string, r *http.Request) error {
	log.WithField("file", tempFilename).Info("Handling chunked upload to temporary file")

	// Ensure the directory exists
	absDirectory := filepath.Dir(tempFilename)
	err := os.MkdirAll(absDirectory, os.ModePerm)
	if err != nil {
		log.WithError(err).Errorf("Failed to create directory %s for chunked upload", absDirectory)
		return fmt.Errorf("failed to create directory %s: %w", absDirectory, err)
	}

	targetFile, err := os.OpenFile(tempFilename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.WithError(err).Error("Failed to open temporary file for chunked upload")
		return err
	}
	defer targetFile.Close()

	writer := bufio.NewWriterSize(targetFile, int(conf.ChunkSize))
	buffer := make([]byte, conf.ChunkSize)

	totalBytes := int64(0)
	for {
		n, err := r.Body.Read(buffer)
		if n > 0 {
			totalBytes += int64(n)
			_, writeErr := writer.Write(buffer[:n])
			if writeErr != nil {
				log.WithError(writeErr).Error("Failed to write chunk to temporary file")
				return writeErr
			}
		}
		if err != nil {
			if err == io.EOF {
				break // Finished reading the body
			}
			log.WithError(err).Error("Error reading from request body")
			return err
		}
	}

	err = writer.Flush()
	if err != nil {
		log.WithError(err).Error("Failed to flush buffer to temporary file")
		return err
	}

	log.WithFields(logrus.Fields{
		"temp_file":   tempFilename,
		"total_bytes": totalBytes,
	}).Info("Chunked upload completed successfully")

	uploadSizeBytes.Observe(float64(totalBytes))
	return nil
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

// MonitorRedisHealth periodically checks Redis connectivity and logs the status.
func MonitorRedisHealth(ctx context.Context, client *redis.Client, checkInterval time.Duration) {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping Redis health monitor.")
			return
		case <-ticker.C:
			err := client.Ping(ctx).Err()
			if err != nil {
				log.WithError(err).Error("Redis health check failed")
				// Update connection status
				mu.Lock()
				if redisConnected {
					redisConnected = false
					log.Warn("Redis connection lost")
				}
				mu.Unlock()
				// Optionally implement fallback logic here
			} else {
				log.Info("Redis health check succeeded")
				// Update connection status
				mu.Lock()
				if !redisConnected {
					redisConnected = true
					log.Info("Redis connection restored")
				}
				mu.Unlock()
			}
		}
	}
}

// Monitor network changes
func monitorNetwork(ctx context.Context) {
	currentIP := getCurrentIPAddress() // Placeholder for the current IP address

	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping network monitor.")
			return
		case <-time.After(10 * time.Second):
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

// Handle network events
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
			}
			// Additional event types can be handled here
		}
	}
}

// Get current IP address (example)
func getCurrentIPAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.WithError(err).Error("Failed to get network interfaces")
		return ""
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue // Skip interfaces that are down or loopback
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
		ctxShutdown, shutdownCancel := context.WithTimeout(context.Background(), time.Duration(conf.GracefulShutdownTimeout)*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(ctxShutdown); err != nil {
			log.WithError(err).Fatal("Server Shutdown Failed")
		}

		// Close Redis Client
		if redisClient != nil {
			if err := redisClient.Close(); err != nil {
				log.WithError(err).Error("Error closing Redis client")
			} else {
				log.Info("Redis client closed successfully")
			}
		}

		// Signal other goroutines to stop
		cancel()

		// Close the upload and scan queues and network events channel
		close(uploadQueue)
		close(scanQueue)
		close(networkEvents)

		log.Info("Server gracefully stopped.")
		os.Exit(0)
	}()
}

// Start file cleanup routine
func startFileCleanup(ctx context.Context, storeDir string, ttl time.Duration) {
	ticker := time.NewTicker(1 * time.Hour) // Run cleanup every hour
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping file cleanup routine.")
			return
		case <-ticker.C:
			log.Info("Running file cleanup routine.")
			cleanupFiles(storeDir, ttl)
		}
	}
}

// Cleanup expired files with deduplication consideration
func cleanupFiles(storeDir string, ttl time.Duration) {
	now := time.Now()
	err := filepath.Walk(storeDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.WithError(err).Errorf("Error accessing path %s", path)
			return nil // Continue walking
		}

		// Skip directories ending with "_versions" if versioning is enabled
		if conf.EnableVersioning && info.IsDir() && strings.HasSuffix(info.Name(), "_versions") {
			return filepath.SkipDir
		}

		if info.IsDir() {
			return nil // Skip directories
		}

		// If deduplication is enabled, handle reference counting
		if conf.DeduplicationEnabled && conf.RedisEnabled && redisConnected && redisClient != nil {
			// Assume that files in StoreDir are stored by checksum
			checksum := info.Name()
			checksumKey := fmt.Sprintf("checksum:%s", checksum)

			// Check the last modified time of the stored file
			if now.Sub(info.ModTime()) > ttl {
				// Remove the checksum mapping and check reference count
				// Get the number of filenames referencing this checksum
				refCount, err := redisClient.SCard(context.Background(), checksumKey).Result()
				if err != nil {
					log.WithError(err).Errorf("Failed to get reference count for checksum %s", checksum)
					return nil
				}

				if refCount == 0 {
					// No references, safe to delete the stored file
					err := os.Remove(path)
					if err != nil {
						log.WithError(err).Errorf("Failed to delete stored file %s", path)
					} else {
						log.WithField("file", path).Info("Deleted expired stored file")
						deletedFilesTotal.Inc()
					}
				} else {
					log.WithFields(logrus.Fields{
						"checksum":    checksum,
						"ref_count":   refCount,
						"file":        path,
						"expiry_time": info.ModTime().Add(ttl),
					}).Info("Stored file has active references; skipping deletion")
				}
			}
		} else {
			// Standard cleanup without deduplication
			if now.Sub(info.ModTime()) > ttl {
				err := os.Remove(path)
				if err != nil {
					log.WithError(err).Errorf("Failed to delete file %s", path)
				} else {
					log.WithField("file", path).Info("Deleted expired file")
					deletedFilesTotal.Inc() // Increment Prometheus counter
				}
			}
		}

		return nil
	})

	if err != nil {
		log.WithError(err).Error("Error during file cleanup")
	}
}

// Example function that uses Redis, demonstrating how to use the `r` parameter
func exampleRedisUsage(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	connected := redisConnected
	mu.RUnlock()

	if !connected {
		log.Warn("Redis is not connected. Skipping Redis-dependent operation.")
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	// Use `r` to extract parameters or headers as needed
	exampleParam := r.URL.Query().Get("example")
	if exampleParam == "" {
		log.Warn("Missing 'example' parameter in the request")
		http.Error(w, "Missing 'example' parameter", http.StatusBadRequest)
		return
	}

	// Log the example parameter for debugging purposes
	log.Infof("Received 'example' parameter: %s", exampleParam)

	// Perform Redis operation, e.g., checking or setting a value
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Example Redis operation: storing the parameter
	err := redisClient.Set(ctx, "exampleKey", exampleParam, 10*time.Minute).Err()
	if err != nil {
		log.WithError(err).Error("Failed to store value in Redis")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Info("Value successfully stored in Redis")
	w.Header().Set("Content-Type", "text/plain")
	if _, err := w.Write([]byte("Value stored successfully")); err != nil {
		log.WithError(err).Error("Failed to write response")
	}
}
