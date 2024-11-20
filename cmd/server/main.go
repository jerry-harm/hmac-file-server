package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"os/exec"
	"runtime"

	"testing"

	"github.com/BurntSushi/toml"
	"github.com/dutchcoders/go-clamd"
	"github.com/go-redis/redis/v8"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rakyll/magicmime"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	"github.com/sirupsen/logrus"
)

var (
	conf Config

	// Add your Prometheus metrics here
	// uploadsTotal is already declared later in the code
)

// Removed duplicate validateConfig function

// Removed duplicate Config struct

// Removed duplicate readConfig function

// var conf Config

// EncryptStream encrypts data from the input reader to the output writer using AES-CTR mode.
// If AES encryption is disabled in the configuration, it performs a direct copy.
func EncryptStreamIfEnabled(key []byte, in io.Reader, out io.Writer) error {
	switch conf.Encryption.Method {
	case "aes":
		if !conf.AESEnabled {
			// Pass through the data unencrypted
			_, err := io.Copy(out, in)
			return err
		}
		return EncryptStream(key, in, out)
	case "hmac":
		// Implement HMAC signing if applicable
		return SignStream(key, in, out)
	default:
		// Default to passing through
		_, err := io.Copy(out, in)
		return err
	}
}

// IPManagement holds the IP management configuration.
type IPManagement struct {
	IPSource     string `toml:"IPSource"`
	NginxLogFile string `toml:"NginxLogFile"`
}

func DecryptStreamIfEnabled(key []byte, in io.Reader, out io.Writer) error {
	switch conf.Encryption.Method {
	case "aes":
		if !conf.AESEnabled {
			// Pass through the data unencrypted
			_, err := io.Copy(out, in)
			return err
		}
		return DecryptStream(key, in, out)
	case "hmac":
		// Implement HMAC verification if applicable
		return VerifyStream(key, in, out)
	default:
		// Default to passing through
		_, err := io.Copy(out, in)
		return err
	}
}

// Config holds the server configuration.
// Removed duplicate Config struct and redundant import statements

func DetectFileType(filePath string) (string, error) {
	mimeType, err := magicmime.TypeByFile(filePath)
	if err != nil {
		return "", err
	}
	return mimeType, nil
}

// SignStream signs data using HMAC-SHA256.
func SignStream(key []byte, in io.Reader, out io.Writer) error {
	h := hmac.New(sha256.New, key)
	if _, err := io.Copy(h, in); err != nil {
		return err
	}
	signature := h.Sum(nil)
	if _, err := out.Write(signature); err != nil {
		return err
	}
	return nil
}

// VerifyStream verifies data using HMAC-SHA256.
func VerifyStream(key []byte, in io.Reader, out io.Writer) error {
	h := hmac.New(sha256.New, key)
	if _, err := io.Copy(h, in); err != nil {
		return err
	}
	signature := h.Sum(nil)
	if _, err := out.Write(signature); err != nil {
		return err
	}
	return nil
}

// EncryptStream encrypts data using AES-CTR mode.
func EncryptStream(key []byte, in io.Reader, out io.Writer) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	stream := cipher.NewCTR(block, iv)
	if _, err := out.Write(iv); err != nil {
		return err
	}
	writer := &cipher.StreamWriter{S: stream, W: out}
	_, err = io.Copy(writer, in)
	return err
}

// DecryptStream decrypts data using AES-CTR mode.
func DecryptStream(key []byte, in io.Reader, out io.Writer) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(in, iv); err != nil {
		return err
	}

	stream := cipher.NewCTR(block, iv)
	reader := &cipher.StreamReader{S: stream, R: in}
	_, err = io.Copy(out, reader)
	return err
}

func initClamAV() (*clamd.Clamd, error) {
	socket := conf.ClamAVSocket
	var client *clamd.Clamd

	if strings.HasPrefix(socket, "/") {
		// UNIX socket
		client = clamd.NewClamd("unix:" + socket)
	} else if strings.HasPrefix(socket, "tcp:") {
		// TCP socket
		client = clamd.NewClamd(socket)
	} else {
		return nil, fmt.Errorf("invalid ClamAV socket format")
	}

	if client == nil {
		return nil, fmt.Errorf("failed to create ClamAV client")
	}

	if err := client.Ping(); err != nil {
		return nil, fmt.Errorf("ClamAV ping failed: %w", err)
	}

	log.Info("ClamAV initialized successfully.")
	return client, nil
}

// Config holds the server configuration.
type Config struct {
	ListenIP                  string   `toml:"ListenIP"`   // IP address to bind the server to
	ListenPort                string   `toml:"ListenPort"` // Port to bind the server to
	UnixSocket                bool     `toml:"UnixSocket"`
	Secret                    string   `toml:"Secret"`
	StoreDir                  string   `toml:"StoreDir"`
	UploadSubDir              string   `toml:"UploadSubDir"`
	LoggingEnabled            bool     `toml:"LoggingEnabled"`
	LogLevel                  string   `toml:"LogLevel"`
	LogFile                   string   `toml:"LogFile"`
	MetricsEnabled            bool     `toml:"MetricsEnabled"`
	MetricsPort               string   `toml:"MetricsPort"`
	FileTTL                   string   `toml:"FileTTL"`
	ResumableUploadsEnabled   bool     `toml:"ResumableUploadsEnabled"`
	ResumableDownloadsEnabled bool     `toml:"ResumableDownloadsEnabled"`
	EnableVersioning          bool     `toml:"EnableVersioning"`
	MaxVersions               int      `toml:"MaxVersions"`
	ChunkedUploadsEnabled     bool     `toml:"ChunkedUploadsEnabled"`
	ChunkSize                 int64    `toml:"ChunkSize"`
	AllowedExtensions         []string `toml:"AllowedExtensions"`
	NumWorkers                int      `toml:"NumWorkers"`
	UploadQueueSize           int      `toml:"UploadQueueSize"`
	ReadTimeout               string   `toml:"ReadTimeout"`
	WriteTimeout              string   `toml:"WriteTimeout"`
	IdleTimeout               string   `toml:"IdleTimeout"`
	AESEnabled                bool     `toml:"AESEnabled"`
	ClamAVEnabled             bool     `toml:"ClamAVEnabled"`
	ClamAVSocket              string   `toml:"ClamAVSocket"`
	NumScanWorkers            int      `toml:"NumScanWorkers"`
	RedisEnabled              bool     `toml:"RedisEnabled"`
	RedisDBIndex              int      `toml:"RedisDBIndex"`
	RedisAddr                 string   `toml:"RedisAddr"`
	RedisPassword             string   `toml:"RedisPassword"`
	RedisHealthCheckInterval  string   `toml:"RedisHealthCheckInterval"`
	GracefulShutdownTimeout   int      `toml:"GracefulShutdownTimeout"`
	EnableIPManagement        bool     `toml:"EnableIPManagement"`
	AllowedIPs                []string `toml:"AllowedIPs"`
	BlockedIPs                []string `toml:"BlockedIPs"`
	IPCheckInterval           string   `toml:"IPCheckInterval"`
	EnableRateLimiting        bool     `toml:"EnableRateLimiting"`
	RequestsPerMinute         int      `toml:"RequestsPerMinute"`
	RateLimitInterval         string   `toml:"RateLimitInterval"`
	Fail2BanEnabled           bool     `toml:"Fail2BanEnabled"`
	Fail2BanCommand           string   `toml:"Fail2BanCommand"`
	Fail2BanJail              string   `toml:"Fail2BanJail"`
	DeduplicationEnabled      bool     `toml:"DeduplicationEnabled"`

	// IPManagement holds the IP management configuration.
	IPManagement struct {
		IPSource     string `toml:"IPSource"`     // "header" or "nginx-log"
		NginxLogFile string `toml:"NginxLogFile"` // Required if IPSource is "nginx-log"
	} `toml:"IPManagement"`

	// Encryption holds the encryption configuration.
	Encryption struct {
		Method string `toml:"Method"` // "hmac" or "aes"
	} `toml:"Encryption"`

	// TLS holds the TLS configuration.
	TLS struct {
		EnableTLS  bool     `toml:"EnableTLS"`
		CertDir    string   `toml:"CertDir"`
		Hostnames  []string `toml:"Hostnames"`
		UseStaging bool     `toml:"UseStaging"`
	} `toml:"TLS"`
}

// UploadTask represents a file upload task.
type UploadTask struct {
	AbsFilename string
	Request     *http.Request
	Result      chan error
}

// ScanTask represents a file scan task.
type ScanTask struct {
	AbsFilename string
	Result      chan error
}

// NetworkEvent represents a network-related event.
type NetworkEvent struct {
	Type    string
	Details string
}

var (
	versionString = "2.1.0pre"
	log           = logrus.New()

	// Channels
	uploadQueue   chan UploadTask
	scanQueue     chan ScanTask
	networkEvents chan NetworkEvent

	// Caches and Clients
	fileInfoCache   *cache.Cache
	requestCounters *cache.Cache
	redisClient     *redis.Client
	clamClient      *clamd.Clamd

	// Metrics
	uploadDuration       = prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: "hmac", Name: "file_server_upload_duration_seconds", Help: "Histogram of file upload duration in seconds."})
	uploadErrorsTotal    = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "hmac", Name: "file_server_upload_errors_total", Help: "Total number of file upload errors."})
	uploadsTotal         = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "hmac", Name: "file_server_uploads_total", Help: "Total number of successful file uploads."})
	downloadDuration     = prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: "hmac", Name: "file_server_download_duration_seconds", Help: "Histogram of file download duration in seconds."})
	downloadsTotal       = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "hmac", Name: "file_server_downloads_total", Help: "Total number of successful file downloads."})
	downloadErrorsTotal  = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "hmac", Name: "file_server_download_errors_total", Help: "Total number of file download errors."})
	memoryUsage          = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "hmac", Name: "memory_usage_bytes", Help: "Current memory usage in bytes."})
	cpuUsage             = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "hmac", Name: "cpu_usage_percent", Help: "Current CPU usage as a percentage."})
	requestsTotalCounter = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "hmac", Name: "http_requests_total", Help: "Total number of HTTP requests received, labeled by method and path."}, []string{"method", "path"})
	goroutines           = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "hmac", Name: "goroutines_count", Help: "Current number of goroutines."})
	uploadSizeBytes      = prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: "hmac", Name: "file_server_upload_size_bytes", Help: "Histogram of uploaded file sizes in bytes.", Buckets: prometheus.ExponentialBuckets(100, 10, 8)})
	downloadSizeBytes    = prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: "hmac", Name: "file_server_download_size_bytes", Help: "Histogram of downloaded file sizes in bytes.", Buckets: prometheus.ExponentialBuckets(100, 10, 8)})
	infectedFilesTotal   = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "hmac", Name: "infected_files_total", Help: "Total number of infected files detected."})
	deletedFilesTotal    = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "hmac", Name: "file_deletions_total", Help: "Total number of files deleted based on FileTTL."})
	uploadQueueLength    = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "hmac", Name: "upload_queue_length", Help: "Current length of the upload queue."})
	scanQueueLength      = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "hmac", Name: "scan_queue_length", Help: "Current length of the scan queue."})
	rateLimitInterval    time.Duration
)

const defaultRateLimitInterval = "1m"

// Updated main function to conditionally start file cleanup based on FileTTL
// main is the entry point for the HMAC file server application. It performs the following tasks:
// 1. Parses command-line flags.
// 2. Reads and validates the configuration from a TOML file.
// 3. Sets up logging and system metrics.
// 4. Initializes optional services like Redis and ClamAV if enabled in the configuration.
// 5. Creates necessary directories and initializes caches.
// 6. Sets up rate limiting if enabled in the configuration.
// 7. Initializes channels for upload and scan tasks, and network events.
// 8. Starts various background goroutines for monitoring and handling tasks.
// 9. Configures and starts the HTTP server with specified timeouts.
// 10. Optionally starts a metrics server if enabled in the configuration.
// 11. Sets up graceful shutdown handling.
// 12. Starts the main server, either on a TCP port or a Unix socket based on the configuration.
func main() {
	flag.Parse()
	if err := readConfig("./config.toml", &conf); err != nil {
		log.Fatalf("Error reading config: %v", err)
	}
	validateConfig(&conf)

	setupLogging()
	logSystemInfo()
	initMetrics()

	if conf.RedisEnabled {
		err := initRedisWithRetry(3, 5*time.Second)
		if err != nil {
			log.Warnf("Redis not initialized: %v", err)
		}
	}

	if conf.ClamAVEnabled {
		if c, err := initClamAV(); err != nil {
			log.WithError(err).Warn("ClamAV initialization failed.")
			conf.ClamAVEnabled = false
		} else {
			clamClient = c
			log.Info("ClamAV initialized.")
		}
	}

	if err := os.MkdirAll(conf.StoreDir, os.ModePerm); err != nil {
		log.Fatalf("StoreDir creation failed: %v", err)
	}

	fileInfoCache = cache.New(5*time.Minute, 10*time.Minute)

	if conf.EnableRateLimiting {
		var err error
		rateLimitInterval, err = ParseCustomDuration(conf.RateLimitInterval)
		if err != nil {
			log.Fatalf("Invalid RateLimitInterval: %v", err)
		}
		requestCounters = cache.New(rateLimitInterval, 2*rateLimitInterval)
	}

	uploadQueue = make(chan UploadTask, conf.UploadQueueSize)
	if conf.ClamAVEnabled {
		scanQueue = make(chan ScanTask, conf.UploadQueueSize)
	}
	networkEvents = make(chan NetworkEvent, 100)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go monitorNetwork(ctx)
	go handleNetworkEvents(ctx)
	go updateSystemMetrics(ctx)
	go monitorQueueLengths(ctx)

	if conf.RedisEnabled && redisClient != nil {
		interval, err := parseHealthCheckInterval(conf.RedisHealthCheckInterval)
		if err != nil {
			log.Fatalf("Invalid RedisHealthCheckInterval: %v", err)
		}
		go MonitorRedisHealth(ctx, redisClient, interval)
	}

	initializeWorkerPools(ctx)

	fileTTLDuration, err := ParseCustomDuration(conf.FileTTL)
	if err != nil {
		log.Fatalf("Invalid FileTTL: %v", err)
	}
	if fileTTLDuration > 0 {
		log.Infof("FileTTL set to %v, starting file cleanup routine.", fileTTLDuration)
		go startFileCleanup(ctx, conf.StoreDir, fileTTLDuration)
	} else {
		log.Info("FileTTL is disabled. Files will not be deleted.")
	}

	router := setupRouter()

	readTimeout, err := time.ParseDuration(conf.ReadTimeout)
	if err != nil {
		log.Fatalf("Invalid ReadTimeout: %v", err)
	}
	writeTimeout, err := time.ParseDuration(conf.WriteTimeout)
	if err != nil {
		log.Fatalf("Invalid WriteTimeout: %v", err)
	}
	idleTimeout, err := time.ParseDuration(conf.IdleTimeout)
	if err != nil {
		log.Fatalf("Invalid IdleTimeout: %v", err)
	}

	server := &http.Server{
		Addr:         conf.ListenPort,
		Handler:      router,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	if conf.MetricsEnabled {
		go func() {
			log.Infof("Metrics server running on %s", conf.MetricsPort)
			http.Handle("/metrics", promhttp.Handler())
			err := http.ListenAndServe(conf.MetricsPort, nil)
			if err != nil {
				log.WithError(err).Fatal("Metrics server failed")
			}
		}()
	}

	setupGracefulShutdown(server, cancel)

	log.Infof("Starting HMAC file server %s...", versionString)
	if conf.UnixSocket {
		listener, err := net.Listen("unix", conf.ListenPort)
		if err != nil {
			log.WithError(err).Fatal("Unix socket listen failed.")
		}
		defer listener.Close()
		err = server.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("Server failed.")
		}
	} else {
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("Server failed.")
		}
	}
}

// Updated readConfig function to handle FileTTL correctly
func readConfig(path string, conf *Config) error {
	if _, err := toml.DecodeFile(path, conf); err != nil {
		return err
	}

	// Set defaults
	if conf.ChunkSize == 0 {
		conf.ChunkSize = 1 << 20 // 1MB
	}
	if conf.ReadTimeout == "" {
		conf.ReadTimeout = "2h"
	}
	if conf.WriteTimeout == "" {
		conf.WriteTimeout = "2h"
	}
	if conf.IdleTimeout == "" {
		conf.IdleTimeout = "2h"
	}
	if conf.RedisEnabled {
		if conf.RedisHealthCheckInterval == "" {
			conf.RedisHealthCheckInterval = "30s"
		}
		// RedisDBIndex defaults to 0 if not set
	}
	if conf.EnableIPManagement && conf.IPCheckInterval == "" {
		conf.IPCheckInterval = "60s"
	}
	if conf.EnableRateLimiting && conf.RateLimitInterval == "" {
		conf.RateLimitInterval = defaultRateLimitInterval
	}
	if conf.ClamAVEnabled && conf.NumScanWorkers <= 0 {
		conf.NumScanWorkers = 5
	}
	if conf.Encryption.Method == "" {
		conf.Encryption.Method = "aes" // Default to AES
	}

	// Validate Encryption method
	if conf.Encryption.Method != "hmac" && conf.Encryption.Method != "aes" {
		log.Warnf("Invalid Encryption Method '%s', defaulting to 'aes'.", conf.Encryption.Method)
		conf.Encryption.Method = "aes"
	}

	log.WithFields(logrus.Fields{
		"ListenPort":         conf.ListenPort,
		"UnixSocket":         conf.UnixSocket,
		"StoreDir":           conf.StoreDir,
		"LoggingEnabled":     conf.LoggingEnabled,
		"LogLevel":           conf.LogLevel,
		"MetricsEnabled":     conf.MetricsEnabled,
		"FileTTL":            conf.FileTTL,
		"EnableIPManagement": conf.EnableIPManagement,
		"IPSource":           conf.IPManagement.IPSource,
		"NginxLogFile":       conf.IPManagement.NginxLogFile,
		"EncryptionMethod":   conf.Encryption.Method,
		// Add other relevant configurations
	}).Info("Configuration loaded successfully")

	return nil
}

func setupLogging() {
	level, err := logrus.ParseLevel(conf.LogLevel)
	if err != nil {
		log.Fatalf("Invalid log level: %v", err)
	}
	log.SetLevel(level)

	if conf.LoggingEnabled && conf.LogFile != "" {
		file, err := os.OpenFile(conf.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		log.SetOutput(file)
	} else {
		log.SetOutput(os.Stdout)
	}

	log.Infof("Logging initialized. Level: %s, Output: %s", conf.LogLevel, conf.LogFile)
}

func initMetrics() {
	if conf.MetricsEnabled {
		prometheus.MustRegister(uploadDuration, uploadErrorsTotal, uploadsTotal, downloadDuration, downloadsTotal, downloadErrorsTotal,
			memoryUsage, cpuUsage, requestsTotalCounter, goroutines, uploadSizeBytes, downloadSizeBytes, infectedFilesTotal, deletedFilesTotal, uploadQueueLength, scanQueueLength)
	}
}

func initRedisWithRetry(maxRetries int, delay time.Duration) error {
	for i := 0; i < maxRetries; i++ {
		if err := initRedis(); err == nil {
			return nil
		}
		log.Warnf("Redis init failed, retrying in %v...", delay)
		time.Sleep(delay)
	}
	return fmt.Errorf("failed to initialize Redis after %d attempts", maxRetries)
}

var (
	muRedis        sync.RWMutex
	redisConnected bool = false
)

func initRedis() error {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     conf.RedisAddr,
		Password: conf.RedisPassword,
		DB:       conf.RedisDBIndex,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := redisClient.Ping(ctx).Result(); err != nil {
		return err
	}

	muRedis.Lock()
	redisConnected = true
	muRedis.Unlock()
	log.Info("Connected to Redis.")
	return nil
}

func logSystemInfo() {
	log.Info("========================================")
	log.Infof("       HMAC File Server - %s          ", versionString)
	log.Info("  Secure File Handling with HMAC Auth   ")
	log.Info("========================================")

	log.Info("Features: Prometheus Metrics, Chunked Uploads, ClamAV Scanning, Deduplication")
	log.Info("Build Date: 2024-11-20")

	log.Infof("OS: %s, Arch: %s, CPUs: %d, Go: %s", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())

	v, _ := mem.VirtualMemory()
	log.Infof("Memory - Total: %v MB, Free: %v MB, Used: %v MB", v.Total/1024/1024, v.Free/1024/1024, v.Used/1024/1024)

	cpuInfo, _ := cpu.Info()
	for _, info := range cpuInfo {
		log.Infof("CPU: %s, Cores: %d, MHz: %.2f", info.ModelName, info.Cores, info.Mhz)
	}

	partitions, _ := disk.Partitions(false)
	for _, p := range partitions {
		usage, _ := disk.Usage(p.Mountpoint)
		log.Infof("Disk: %s, Total: %v GB, Free: %v GB, Used: %v GB", p.Mountpoint, usage.Total/1e9, usage.Free/1e9, usage.Used/1e9)
	}

	hInfo, _ := host.Info()
	log.Infof("Hostname: %s, Uptime: %v seconds, Boot Time: %v, Platform: %s %s %s, Kernel: %s",
		hInfo.Hostname, hInfo.Uptime, time.Unix(int64(hInfo.BootTime), 0),
		hInfo.Platform, hInfo.PlatformFamily, hInfo.PlatformVersion, hInfo.KernelVersion)
}

func initializeWorkerPools(ctx context.Context) {
	for i := 0; i < conf.NumWorkers; i++ {
		go uploadWorker(ctx, i)
	}
	log.Infof("Initialized %d upload workers", conf.NumWorkers)

	if conf.ClamAVEnabled && clamClient != nil {
		for i := 0; i < conf.NumScanWorkers; i++ {
			go scanWorker(ctx, i)
		}
		log.Infof("Initialized %d scan workers", conf.NumScanWorkers)
	}
}

func uploadWorker(ctx context.Context, id int) {
	log.WithField("worker_id", id).Info("Upload worker started")
	for {
		select {
		case <-ctx.Done():
			log.WithField("worker_id", id).Info("Upload worker stopping")
			return
		case task, ok := <-uploadQueue:
			if !ok {
				log.WithField("worker_id", id).Info("Upload queue closed")
				return
			}
			select {
			case <-ctx.Done():
				log.WithField("worker_id", id).Info("Upload worker stopping")
				return
			default:
				// Proceed with processing
			}
			var err error
			if err = processUpload(task); err != nil {
				log.WithFields(logrus.Fields{"worker_id": id, "file": task.AbsFilename, "error": err}).Error("Upload failed")
				uploadErrorsTotal.Inc()
				blockIPFail2Ban(getClientIP(task.Request))
			} else {
				log.WithFields(logrus.Fields{"worker_id": id, "file": task.AbsFilename}).Info("Upload succeeded")
				uploadsTotal.Inc()
			}
			task.Result <- err
			close(task.Result)
		}
	}
}

func scanWorker(ctx context.Context, id int) {
	log.WithField("worker_id", id).Info("Scan worker started")
	for {
		select {
		case <-ctx.Done():
			log.WithField("worker_id", id).Info("Scan worker stopping")
			return
		case task, ok := <-scanQueue:
			if !ok {
				log.WithField("worker_id", id).Info("Scan queue closed")
				return
			}
			var err error
			if err = scanFileWithClamAV(task.AbsFilename); err != nil {
				log.WithFields(logrus.Fields{"worker_id": id, "file": task.AbsFilename, "error": err}).Error("Scan failed")
			} else {
				log.WithFields(logrus.Fields{"worker_id": id, "file": task.AbsFilename}).Info("Scan succeeded")
			}
			task.Result <- err
			close(task.Result)
		}
	}
}

func processUpload(task UploadTask) error {
	absFilename := task.AbsFilename
	tempFilename := absFilename + ".tmp"
	r := task.Request

	startTime := time.Now()
	var err error

	defer func() {
		if err != nil {
			os.Remove(tempFilename)
		}
	}()

	if conf.ChunkedUploadsEnabled {
		err = handleChunkedUpload(tempFilename, r)
	} else {
		err = createFile(tempFilename, r)
	}
	if err != nil {
		uploadDuration.Observe(time.Since(startTime).Seconds())
		return err
	}

	if conf.ClamAVEnabled && clamClient != nil {
		if err = scanFileWithClamAV(tempFilename); err != nil {
			os.Remove(tempFilename)
			uploadErrorsTotal.Inc()
			return err
		}
	}

	if conf.DeduplicationEnabled && conf.RedisEnabled && redisConnected && redisClient != nil {
		checksum, err := CalculateChecksum(tempFilename)
		if err != nil {
			os.Remove(tempFilename)
			uploadErrorsTotal.Inc()
			return err
		}
		checksumKey := fmt.Sprintf("checksum:%s", checksum)
		filenameKey := fmt.Sprintf("filename:%s", filepath.Base(absFilename))

		exists, err := redisClient.Exists(context.Background(), checksumKey).Result()
		if err != nil {
			os.Remove(tempFilename)
			uploadErrorsTotal.Inc()
			return err
		}

		if exists > 0 {
			err = redisClient.SAdd(context.Background(), checksumKey, filepath.Base(absFilename)).Err()
			if err != nil {
				os.Remove(tempFilename)
				uploadErrorsTotal.Inc()
				return err
			}
			err = redisClient.Set(context.Background(), filenameKey, checksum, 0).Err()
			if err != nil {
				os.Remove(tempFilename)
				uploadErrorsTotal.Inc()
				return err
			}
			os.Remove(tempFilename)
			uploadDuration.Observe(time.Since(startTime).Seconds())
			uploadsTotal.Inc()
			return nil
		}

		finalPath := filepath.Join(conf.StoreDir, checksum)
		err = os.Rename(tempFilename, finalPath)
		if err != nil {
			os.Remove(tempFilename)
			uploadErrorsTotal.Inc()
			return err
		}

		err = redisClient.SAdd(context.Background(), checksumKey, filepath.Base(absFilename)).Err()
		if err != nil {
			return err
		}
		err = redisClient.Set(context.Background(), filenameKey, checksum, 0).Err()
		if err != nil {
			return err
		}
		uploadDuration.Observe(time.Since(startTime).Seconds())
		uploadsTotal.Inc()
		return nil
	}

	if conf.EnableVersioning {
		exists, _ := fileExists(absFilename)
		if exists {
			err := versionFile(absFilename)
			if err != nil {
				os.Remove(tempFilename)
				return err
			}
		}
	}

	uploadDuration.Observe(time.Since(startTime).Seconds())
	uploadsTotal.Inc()
	return nil
}

func handleDownload(w http.ResponseWriter, r *http.Request, absFilename, fileStorePath string) {
	var actualFilePath string
	var fileInfo os.FileInfo
	var err error

	if conf.DeduplicationEnabled && conf.RedisEnabled && redisConnected && redisClient != nil {
		filenameKey := fmt.Sprintf("filename:%s", filepath.Base(absFilename))
		checksum, err := redisClient.Get(context.Background(), filenameKey).Result()
		if err != nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			downloadErrorsTotal.Inc()
			return
		}
		actualFilePath = filepath.Join(conf.StoreDir, checksum)
		fileInfo, err = getFileInfo(actualFilePath)
		if err != nil || fileInfo.IsDir() {
			http.Error(w, "Not Found", http.StatusNotFound)
			downloadErrorsTotal.Inc()
			return
		}
	} else {
		fileInfo, err = getFileInfo(absFilename)
		if err != nil || fileInfo.IsDir() {
			http.Error(w, "Not Found", http.StatusNotFound)
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

	if conf.ResumableDownloadsEnabled {
		handleResumableDownload(actualFilePath, w, r, fileInfo.Size())
		return
	}

	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))
		downloadsTotal.Inc()
		return
	}

	startTime := time.Now()
	http.ServeFile(w, r, actualFilePath)
	downloadDuration.Observe(time.Since(startTime).Seconds())
	downloadSizeBytes.Observe(float64(fileInfo.Size()))
	downloadsTotal.Inc()
}

func createFile(tempFilename string, r *http.Request) error {
	if err := os.MkdirAll(filepath.Dir(tempFilename), os.ModePerm); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	// Change permissions from 0600 to 0644
	file, err := os.OpenFile(tempFilename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriterSize(file, 4<<20) // 4MB buffer
	totalBytes := int64(0)
	buffer := make([]byte, 4<<20)

	for {
		n, err := r.Body.Read(buffer)
		if n > 0 {
			totalBytes += int64(n)
			if _, writeErr := writer.Write(buffer[:n]); writeErr != nil {
				return fmt.Errorf("write file: %w", writeErr)
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("read body: %w", err)
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush writer: %w", err)
	}

	uploadSizeBytes.Observe(float64(totalBytes))
	return nil
}

func handleChunkedUpload(tempFilename string, r *http.Request) error {
	log.Infof("Handling chunked upload: %s", tempFilename)

	if err := os.MkdirAll(filepath.Dir(tempFilename), os.ModePerm); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	// Change permissions from 0600 to 0644
	file, err := os.OpenFile(tempFilename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriterSize(file, int(conf.ChunkSize))
	totalBytes := int64(0)
	buffer := make([]byte, conf.ChunkSize)

	for {
		n, err := r.Body.Read(buffer)
		if n > 0 {
			totalBytes += int64(n)
			if _, writeErr := writer.Write(buffer[:n]); writeErr != nil {
				return fmt.Errorf("write chunk: %w", writeErr)
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("read body: %w", err)
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush writer: %w", err)
	}

	uploadSizeBytes.Observe(float64(totalBytes))
	return nil
}

func fileExists(path string) (bool, int64) {
	if info, found := fileInfoCache.Get(path); found {
		if fi, ok := info.(os.FileInfo); ok {
			return !fi.IsDir(), fi.Size()
		}
	}

	fi, err := os.Stat(path)
	if err != nil {
		return false, 0
	}
	fileInfoCache.Set(path, fi, cache.DefaultExpiration)
	return !fi.IsDir(), fi.Size()
}
func scanFileWithClamAV(path string) error {
	resultChannel, err := clamClient.ScanFile(path)
	if err != nil {
		return fmt.Errorf("scan error: %w", err)
	}

	var scanResult *clamd.ScanResult
	for result := range resultChannel {
		scanResult = result
	}

	if scanResult == nil {
		return fmt.Errorf("no scan result")
	}

	switch scanResult.Status {
	case clamd.RES_OK:
		return nil
	case clamd.RES_FOUND:
		infectedFilesTotal.Inc()
		return fmt.Errorf("virus detected: %s", scanResult.Description)
	default:
		return fmt.Errorf("unexpected scan status: %s", scanResult.Description)
	}
}

func handleResumableDownload(filePath string, w http.ResponseWriter, r *http.Request, size int64) {
	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		serveFile(w, r, filePath, size)
		return
	}

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

	end := size - 1
	if ranges[1] != "" {
		end, err = strconv.ParseInt(ranges[1], 10, 64)
		if err != nil || start > end {
			http.Error(w, "Invalid Range", http.StatusRequestedRangeNotSatisfiable)
			downloadErrorsTotal.Inc()
			return
		}
	}

	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
	w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusPartialContent)

	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		downloadErrorsTotal.Inc()
		return
	}
	defer file.Close()

	if _, err := file.Seek(start, 0); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		downloadErrorsTotal.Inc()
		return
	}

	buffer := make([]byte, 32<<10) // 32KB
	remaining := end - start + 1
	startTime := time.Now()

	for remaining > 0 {
		if int64(len(buffer)) > remaining {
			buffer = buffer[:remaining]
		}
		n, err := file.Read(buffer)
		if n > 0 {
			if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
				downloadErrorsTotal.Inc()
				return
			}
			remaining -= int64(n)
		}
		if err != nil {
			if err != io.EOF {
				downloadErrorsTotal.Inc()
			}
			break
		}
	}

	downloadDuration.Observe(time.Since(startTime).Seconds())
	downloadSizeBytes.Observe(float64(end - start + 1))
	downloadsTotal.Inc()
}

func serveFile(w http.ResponseWriter, r *http.Request, filePath string, size int64) {
	contentType := mime.TypeByExtension(filepath.Ext(filePath))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)

	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		downloadsTotal.Inc()
		return
	}

	startTime := time.Now()
	http.ServeFile(w, r, filePath)
	downloadDuration.Observe(time.Since(startTime).Seconds())
	downloadSizeBytes.Observe(float64(size))
	downloadsTotal.Inc()
}

func blockIPFail2Ban(ip string) {
	if conf.Fail2BanEnabled {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, conf.Fail2BanCommand, "set", conf.Fail2BanJail, "ban", ip)
		if err := cmd.Run(); err != nil {
			log.Errorf("Fail2Ban block failed for IP %s: %v", ip, err)
			return
		}
		log.Infof("IP %s blocked via Fail2Ban", ip)
	}
}

func getCurrentIPAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.WithError(err).Error("GetInterfaces failed")
		return ""
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			log.WithError(err).Errorf("GetAddrs failed for interface %s", iface.Name)
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

func monitorNetwork(ctx context.Context) {
	defer func() {
		if rec := recover(); rec != nil {
			log.WithField("panic", rec).Error("Recovered from panic in monitorNetwork")
		}
	}()
	currentIP := getCurrentIPAddress()
	for {
		select {
		case <-ctx.Done():
			log.Info("Network monitor stopping.")
			return
		case <-time.After(10 * time.Second):
			newIP := getCurrentIPAddress()
			if newIP != currentIP && newIP != "" {
				currentIP = newIP
				select {
				case networkEvents <- NetworkEvent{Type: "IP_CHANGE", Details: currentIP}:
					log.Infof("IP changed to %s", currentIP)
				default:
					log.Warn("NetworkEvents channel full, dropping IP_CHANGE event.")
				}
			}
		}
	}
}

func handleNetworkEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			log.Info("Network event handler stopping.")
			return
		case event, ok := <-networkEvents:
			if !ok {
				log.Info("NetworkEvents channel closed.")
				return
			}
			switch event.Type {
			case "IP_CHANGE":
				log.Infof("IP change detected: %s", event.Details)
			}
		}
	}
}

func MonitorRedisHealth(ctx context.Context, client *redis.Client, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Redis health monitor stopping.")
			return
		case <-ticker.C:
			if err := client.Ping(ctx).Err(); err != nil {
				muRedis.Lock()
				if redisConnected {
					redisConnected = false
					log.Warn("Redis connection lost.")
				}
				muRedis.Unlock()
			} else {
				muRedis.Lock()
				if !redisConnected {
					redisConnected = true
					log.Info("Redis connection restored.")
				}
				muRedis.Unlock()
			}
		}
	}
}

func rateLimitingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		if isRateLimited(clientIP) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func setupRouter() http.Handler {
	mux := http.NewServeMux()
	subpath := filepath.Join("/", conf.UploadSubDir) + "/"
	mux.HandleFunc(subpath, handleRequest)
	mux.HandleFunc("/example", exampleRedisUsage)

	if conf.MetricsEnabled {
		mux.Handle("/metrics", promhttp.Handler())
	}

	return loggingMiddleware(recoveryMiddleware(rateLimitingMiddleware(mux)))
}

// recoveryMiddleware recovers from panics and logs the error.
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.WithField("panic", rec).Error("Recovered from panic")
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs the details of each HTTP request.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.WithFields(logrus.Fields{
			"method": r.Method,
			"url":    r.URL.String(),
			"time":   time.Since(start),
		}).Info("Handled request")
	})
}

// Updated getClientIP function to utilize IPManagement
func getClientIP(r *http.Request) string {
	switch conf.IPManagement.IPSource {
	case "header":
		return getClientIPFromHeader(r)
	case "nginx-log":
		return getClientIPFromNginxLog(r)
	default:
		log.Warn("Unknown IPSource configuration, defaulting to headers.")
		return getClientIPFromHeader(r)
	}
}

func getClientIPFromHeader(r *http.Request) string {
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.Header.Get("X-Real-IP")
	}
	if clientIP == "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.WithError(err).Warn("SplitHostPort failed")
			return r.RemoteAddr
		}
		clientIP = host
	} else {
		clientIP = strings.Split(clientIP, ",")[0]
	}
	return strings.TrimSpace(clientIP)
}

func isIPAllowed(ip string) bool {
	for _, blocked := range conf.BlockedIPs {
		if ip == blocked {
			return false
		}
	}
	if len(conf.AllowedIPs) > 0 {
		for _, allowed := range conf.AllowedIPs {
			if ip == allowed {
				return true
			}
		}
		return false
	}
	return true
}

func isRateLimited(ip string) bool {
	if !conf.EnableRateLimiting {
		return false
	}
	muRedis.RLock()
	defer muRedis.RUnlock()
	count, found := requestCounters.Get(ip)
	if !found {
		requestCounters.Set(ip, 1, rateLimitInterval)
		return false
	}
	if count.(int) >= conf.RequestsPerMinute {
		return true
	}
	requestCounters.Increment(ip, 1)
	return false
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	log.WithFields(logrus.Fields{
		"method":    r.Method,
		"url":       r.URL.String(),
		"client_ip": clientIP,
	}).Info("Incoming request")

	if conf.EnableIPManagement && !isIPAllowed(clientIP) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	_, fileStorePath, err := parseFilePath(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	absFilename := filepath.Join(conf.StoreDir, fileStorePath)
	if err := validateFilePath(absFilename); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		downloadErrorsTotal.Inc()
		return
	}

	switch r.Method {
	case http.MethodPut:
		handleUpload(w, r, absFilename, fileStorePath, r.URL.Query())
	case http.MethodHead, http.MethodGet:
		handleDownload(w, r, absFilename, fileStorePath)
	case http.MethodOptions:
		w.Header().Set("Allow", "OPTIONS, GET, PUT, HEAD")
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func parseFilePath(path string) (string, string, error) {
	subDir := filepath.Join("/", conf.UploadSubDir)
	fileStorePath := strings.TrimPrefix(path, subDir)
	if fileStorePath == "" || fileStorePath == "/" {
		return "", "", fmt.Errorf("forbidden path")
	}
	fileStorePath = strings.TrimPrefix(fileStorePath, "/")
	fileStorePath, err := url.PathUnescape(fileStorePath)
	if err != nil {
		return "", "", fmt.Errorf("invalid file path")
	}
	return subDir, fileStorePath, nil
}

func validateFilePath(absFilename string) error {
	absStoreDir, err := filepath.Abs(conf.StoreDir)
	if err != nil {
		return fmt.Errorf("internal server error")
	}
	absPath, err := filepath.Abs(absFilename)
	if err != nil || !strings.HasPrefix(absPath, absStoreDir+string(os.PathSeparator)) {
		return fmt.Errorf("forbidden path")
	}
	return nil
}

func handleUpload(w http.ResponseWriter, r *http.Request, absFilename, fileStorePath string, a url.Values) {
	protocolVersion := determineProtocolVersion(a)
	if protocolVersion == "" {
		http.Error(w, "Invalid HMAC parameters", http.StatusForbidden)
		return
	}

	if !validateHMAC(protocolVersion, fileStorePath, r, a) {
		http.Error(w, "Invalid MAC", http.StatusForbidden)
		return
	}

	if protocolVersion == "token" {
		handleTokenProtocol(a.Get("token"))
	}

	if !isExtensionAllowed(fileStorePath) {
		http.Error(w, "Disallowed file extension", http.StatusForbidden)
		uploadErrorsTotal.Inc()
		return
	}

	task := UploadTask{
		AbsFilename: absFilename,
		Request:     r,
		Result:      make(chan error),
	}

	select {
	case uploadQueue <- task:
	default:
		http.Error(w, "Server busy. Try again later.", http.StatusServiceUnavailable)
		uploadErrorsTotal.Inc()
		return
	}

	if err := <-task.Result; err != nil {
		http.Error(w, fmt.Sprintf("Upload failed: %v", err), http.StatusInternalServerError)
		return
	}

	if protocolVersion == "token" {
		deleteToken(a.Get("token"))
	}

	w.WriteHeader(http.StatusCreated)
}

func determineProtocolVersion(a url.Values) string {
	if a.Get("v2") != "" {
		return "v2"
	}
	if a.Get("token") != "" {
		return "token"
	}
	if a.Get("v") != "" {
		return "v"
	}
	return ""
}

func validateHMAC(version, path string, r *http.Request, a url.Values) bool {
	mac := hmac.New(sha256.New, []byte(conf.Secret))
	switch version {
	case "v":
		mac.Write([]byte(fmt.Sprintf("%s %d", path, r.ContentLength)))
	case "v2", "token":
		contentType := mime.TypeByExtension(filepath.Ext(path))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		mac.Write([]byte(fmt.Sprintf("%s\x00%d\x00%s", path, r.ContentLength, contentType)))
	}

	calculatedMAC := mac.Sum(nil)
	providedMACHex := a.Get(version)
	providedMAC, err := hex.DecodeString(providedMACHex)
	if err != nil {
		return false
	}
	return hmac.Equal(calculatedMAC, providedMAC)
}

func handleTokenProtocol(token string) {
	if conf.RedisEnabled && redisConnected && redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := redisClient.Set(ctx, token, "valid", 24*time.Hour).Err(); err != nil {
			log.Error("Failed to store token in Redis")
		}
	}
}

func deleteToken(token string) {
	if conf.RedisEnabled && redisConnected && redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := redisClient.Del(ctx, token).Err(); err != nil {
			log.Error("Failed to delete token from Redis")
		}
	}
}

func isExtensionAllowed(filename string) bool {
	if len(conf.AllowedExtensions) == 0 {
		return true
	}
	ext := strings.ToLower(filepath.Ext(filename))
	for _, allowed := range conf.AllowedExtensions {
		if ext == strings.ToLower(allowed) {
			return true
		}
	}
	return false
}

func CalculateChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hashing: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func startFileCleanup(ctx context.Context, storeDir string, ttl time.Duration) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("File cleanup routine stopping.")
			return
		case <-ticker.C:
			cleanupFiles(storeDir, ttl)
		}
	}
}

func cleanupFiles(storeDir string, ttl time.Duration) {
	now := time.Now()
	err := filepath.Walk(storeDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.WithError(err).Errorf("Access error: %s", path)
			return nil
		}
		if info.IsDir() && conf.EnableVersioning && strings.HasSuffix(info.Name(), "_versions") {
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}

		if conf.DeduplicationEnabled && conf.RedisEnabled && redisConnected && redisClient != nil {
			if now.Sub(info.ModTime()) > ttl {
				checksum := info.Name()
				checksumKey := fmt.Sprintf("checksum:%s", checksum)
				refCount, err := redisClient.SCard(context.Background(), checksumKey).Result()
				if err != nil {
					log.WithError(err).Errorf("Failed SCard for %s", checksum)
					return nil
				}
				if refCount == 0 {
					if err := os.Remove(path); err != nil {
						log.WithError(err).Errorf("Remove failed: %s", path)
					} else {
						deletedFilesTotal.Inc()
						log.Infof("Deleted expired file: %s", path)
					}
				}
			}
		} else {
			if now.Sub(info.ModTime()) > ttl {
				if err := os.Remove(path); err != nil {
					log.WithError(err).Errorf("Remove failed: %s", path)
				} else {
					deletedFilesTotal.Inc()
					log.Infof("Deleted expired file: %s", path)
				}
			}
		}
		return nil
	})
	if err != nil {
		log.WithError(err).Error("File cleanup error")
	}
}

func cleanupOldVersions(versionDir string) error {
	files, err := os.ReadDir(versionDir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}
	if conf.MaxVersions > 0 && len(files) > conf.MaxVersions {
		for _, file := range files[:len(files)-conf.MaxVersions] {
			if err := os.Remove(filepath.Join(versionDir, file.Name())); err != nil {
				return fmt.Errorf("remove old version: %w", err)
			}
			log.Infof("Removed old version: %s", file.Name())
		}
	}
	return nil
}

func versionFile(absFilename string) error {
	versionDir := filepath.Join(absFilename, "_versions")
	if err := os.MkdirAll(versionDir, os.ModePerm); err != nil {
		return fmt.Errorf("mkdir versions: %w", err)
	}

	timestamp := time.Now().Format("20060102-150405")
	versionedFilename := filepath.Join(versionDir, fmt.Sprintf("%s.%s", filepath.Base(absFilename), timestamp))
	if err := os.Rename(absFilename, versionedFilename); err != nil {
		return fmt.Errorf("rename file: %w", err)
	}

	log.Infof("Versioned file to %s", versionedFilename)
	return cleanupOldVersions(versionDir)
}

func getFileInfo(path string) (os.FileInfo, error) {
	if info, found := fileInfoCache.Get(path); found {
		if fi, ok := info.(os.FileInfo); ok {
			return fi, nil
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	fileInfoCache.Set(path, fi, cache.DefaultExpiration)
	return fi, nil
}

func exampleRedisUsage(w http.ResponseWriter, r *http.Request) {
	if !redisConnected {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	exampleParam := r.URL.Query().Get("example")
	if exampleParam == "" {
		http.Error(w, "Missing 'example' parameter", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := redisClient.Set(ctx, "exampleKey", exampleParam, 10*time.Minute).Err(); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Value stored successfully"))
}

// Refactored parseIPFromNginxLog for improved robustness
func parseIPFromNginxLog(logFile, urlPath string) string {
	file, err := os.Open(logFile)
	if err != nil {
		log.WithError(err).Errorf("Failed to open NGINX log file: %s", logFile)
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var ip string

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, urlPath) { // Check if the line corresponds to the requested URL path
			fields := strings.Fields(line)
			if len(fields) > 1 { // Ensure there are enough fields
				ip = fields[0] // First field is the IP address
				log.WithFields(logrus.Fields{
					"url_path": urlPath,
					"ip":       ip,
				}).Info("Extracted IP from NGINX logs")
				break
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.WithError(err).Error("Error reading NGINX log file.")
	}

	if ip == "" {
		log.Warnf("No matching IP found in NGINX logs for path '%s'.", urlPath)
	}

	return ip
}

// Enhanced getClientIPFromNginxLog with logging and fallback
func getClientIPFromNginxLog(r *http.Request) string {
	logFile := conf.IPManagement.NginxLogFile
	if logFile == "" {
		log.Error("NginxLogFile is not configured.")
		return getClientIPFromHeader(r) // Fallback
	}

	urlPath := r.URL.Path
	ip := parseIPFromNginxLog(logFile, urlPath)
	if ip == "" {
		log.WithFields(logrus.Fields{
			"url_path": urlPath,
			"log_file": logFile,
		}).Warn("Failed to find IP in NGINX logs. Falling back to headers.")
		return getClientIPFromHeader(r)
	} else {
		log.WithFields(logrus.Fields{
			"url_path": urlPath,
			"log_file": logFile,
			"ip":       ip,
		}).Info("Successfully parsed IP from NGINX logs")
	}

	return ip
}

// Removed duplicate setupGracefulShutdown function

func ParseCustomDuration(s string) (time.Duration, error) {
	var total time.Duration
	var num string
	for _, char := range s {
		if char >= '0' && char <= '9' {
			num += string(char)
			continue
		}
		val, err := strconv.Atoi(num)
		if err != nil {
			return 0, fmt.Errorf("invalid number: %s", num)
		}
		switch char {
		case 'h':
			total += time.Duration(val) * time.Hour
		case 'd':
			total += time.Duration(val) * 24 * time.Hour
		case 'y':
			total += time.Duration(val) * 365 * 24 * time.Hour
		case 'm':
			total += time.Duration(val) * time.Minute
		default:
			return 0, fmt.Errorf("invalid unit: %c", char)
		}
		num = ""
	}
	if num != "" {
		return 0, fmt.Errorf("trailing number without unit: %s", num)
	}
	return total, nil
}

func parseHealthCheckInterval(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

func monitorQueueLengths(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Queue length monitor stopping.")
			return
		case <-ticker.C:
			uploadQueueLength.Set(float64(len(uploadQueue)))
			if conf.ClamAVEnabled {
				scanQueueLength.Set(float64(len(scanQueue)))
			}
			goroutines.Set(float64(runtime.NumGoroutine()))
		}
	}
}

func updateSystemMetrics(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("System metrics updater stopping.")
			return
		case <-ticker.C:
			if v, err := mem.VirtualMemory(); err == nil {
				memoryUsage.Set(float64(v.Used))
			}
			if cpuPerc, err := cpu.Percent(0, false); err == nil && len(cpuPerc) > 0 {
				cpuUsage.Set(cpuPerc[0])
			}
			goroutines.Set(float64(runtime.NumGoroutine()))
		}
	}
}

func setupGracefulShutdown(server *http.Server, cancel context.CancelFunc) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Info("Shutting down server...")

		ctxShutdown, shutdownCancel := context.WithTimeout(context.Background(), time.Duration(conf.GracefulShutdownTimeout)*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(ctxShutdown); err != nil {
			log.WithError(err).Fatal("Server Shutdown Failed")
		}

		if redisClient != nil {
			if err := redisClient.Close(); err != nil {
				log.WithError(err).Error("Redis client close failed")
			} else {
				log.Info("Redis client closed.")
			}
		}

		cancel()
		close(uploadQueue)
		if conf.ClamAVEnabled {
			close(scanQueue)
		}
		close(networkEvents)

		log.Info("Server gracefully stopped.")
		// Removed os.Exit(0)
	}()
}

// Updated validateConfig function

// Removed unused variable muIP

// Removed duplicate parseIPFromNginxLog function

// Example using Go's testing package
func TestValidateHMAC(t *testing.T) {
	conf.Secret = "testsecret"
	path := "/testpath"
	contentLength := int64(1234)
	version := "v"
	r := &http.Request{
		ContentLength: contentLength,
	}
	a := url.Values{}

	mac := hmac.New(sha256.New, []byte(conf.Secret))
	mac.Write([]byte(fmt.Sprintf("%s %d", path, contentLength)))
	expectedMAC := hex.EncodeToString(mac.Sum(nil))
	a.Set(version, expectedMAC)

	if !validateHMAC(version, path, r, a) {
		t.Error("HMAC validation failed")
	}
}

func validateConfig(config *Config) {
	if config.IPManagement.IPSource == "" {
		logrus.Warning("Invalid IPSource '', defaulting to 'header'.")
		config.IPManagement.IPSource = "header"
	}
	// Add other validation checks as needed
}
