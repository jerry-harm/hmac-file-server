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

// Konfigurationsstruktur
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
	FileTTL                   string   // Optional TTL für Dateiablauf (Standard: "30d")
	ResumableUploadsEnabled   bool     // Resumable Uploads aktivieren/deaktivieren
	ResumableDownloadsEnabled bool     // Resumable Downloads aktivieren/deaktivieren
	EnableVersioning          bool     // Dateiversionierung aktivieren
	MaxVersions               int      // Maximale Anzahl an Dateiversionen
	ChunkingEnabled           bool     // Chunking aktivieren/deaktivieren
	ChunkSize                 int64    // Größe jedes Chunks in Bytes
	AllowedExtensions         []string // Liste erlaubter Dateierweiterungen (z.B. [".txt", ".jpg"])
}

// UploadTask Struktur
type UploadTask struct {
	AbsFilename   string
	FileStorePath string
	Writer        http.ResponseWriter
	Request       *http.Request
	Done          chan error
}

// Event Struktur für Netzwerkänderungen
type NetworkEvent struct {
	Type    string
	Details string
}

var (
	conf           Config
	versionString  string = "v2.0.2"
	log            = logrus.New()
	uploadQueue    chan UploadTask
	networkEvents  = make(chan NetworkEvent, 100)
	fileInfoCache  *cache.Cache

	// Prometheus Metriken
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

func main() {
	// Flags für Konfigurationsdatei
	var configFile string
	flag.StringVar(&configFile, "config", "./config.toml", "Path to configuration file \"config.toml\".")
	flag.Parse()

	// Konfiguration laden
	err := readConfig(configFile, &conf)
	if err != nil {
		log.Fatalln("Error reading configuration file:", err)
	}

	// Dateiinfo-Cache initialisieren
	fileInfoCache = cache.New(5*time.Minute, 10*time.Minute)

	// Speicherverzeichnis erstellen
	err = os.MkdirAll(conf.StoreDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Could not create directory %s: %v", conf.StoreDir, err)
	}
	log.WithField("directory", conf.StoreDir).Info("Store directory is ready")

	// Logging einrichten
	setupLogging()

	// Systeminformationen loggen
	logSystemInfo()

	// Prometheus Metriken initialisieren
	initMetrics()

	// Upload-Queue initialisieren
	uploadQueue = make(chan UploadTask, 5000)

	// Kontext für Goroutinen
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Netzwerküberwachung starten
	go monitorNetwork(ctx)
	go handleNetworkEvents(ctx)

	// Systemmetriken aktualisieren
	go updateSystemMetrics(ctx)

	// Worker-Pool initialisieren
	initializeWorkerPool(ctx)

	// Router einrichten
	router := setupRouter()

	// HTTP-Server konfigurieren
	server := &http.Server{
		Addr:         conf.ListenPort,
		Handler:      router,
		ReadTimeout:  10 * time.Minute,
		WriteTimeout: 10 * time.Minute,
		IdleTimeout:  2 * time.Minute,
	}

	// Metrics-Server starten, falls aktiviert
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

	// Graceful Shutdown einrichten
	setupGracefulShutdown(server, cancel)

	// Server starten
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

// Funktion zur Konfigurationsdatei laden
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

	// Standardwerte für optionale Einstellungen setzen
	if !conf.ResumableUploadsEnabled {
		conf.ResumableUploadsEnabled = false
	}
	if !conf.ResumableDownloadsEnabled {
		conf.ResumableDownloadsEnabled = false
	}
	if conf.MaxVersions == 0 {
		conf.MaxVersions = 0 // Standard: keine maximale Anzahl an Versionen
	}
	if !conf.EnableVersioning {
		conf.EnableVersioning = false // Standard: keine Versionierung
	}
	if !conf.ChunkingEnabled {
		conf.ChunkingEnabled = false // Standard: kein Chunking
	}
	if conf.ChunkSize == 0 {
		conf.ChunkSize = 1048576 // Standard-Chunkgröße: 1MB
	}
	if conf.AllowedExtensions == nil {
		conf.AllowedExtensions = []string{} // Standard: keine Beschränkungen
	}

	return nil
}

// Logging einrichten
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

	// JSON-Formatter für strukturiertes Logging verwenden
	log.SetFormatter(&logrus.JSONFormatter{})
}

// Systeminformationen loggen
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

// Prometheus Metriken initialisieren
func initMetrics() {
	if conf.MetricsEnabled {
		prometheus.MustRegister(uploadDuration, uploadErrorsTotal, uploadsTotal)
		prometheus.MustRegister(downloadDuration, downloadsTotal, downloadErrorsTotal)
		prometheus.MustRegister(memoryUsage, cpuUsage, activeConnections, requestsTotal, goroutines)
		prometheus.MustRegister(uploadSizeBytes, downloadSizeBytes)
	}
}

// Systemmetriken regelmäßig aktualisieren
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

// CORS-Header hinzufügen
func addCORSheaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET, PUT, HEAD")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "7200")
}

// Funktion zum Überprüfen, ob eine Datei existiert und deren Größe zurückgeben
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

// Funktion zur Überprüfung der Dateierweiterung
func isExtensionAllowed(filename string) bool {
	if len(conf.AllowedExtensions) == 0 {
		return true // Keine Beschränkungen, wenn die Liste leer ist
	}
	ext := strings.ToLower(filepath.Ext(filename))
	for _, allowedExt := range conf.AllowedExtensions {
		if strings.ToLower(allowedExt) == ext {
			return true
		}
	}
	return false
}

// Dateiversionierung durch Verschieben der vorhandenen Datei in ein versioniertes Verzeichnis
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
		"versioned_as": versionedFilename,
	}).Info("Versioned old file")
	return cleanupOldVersions(versionDir)
}

// Ältere Versionen entfernen, wenn sie die maximale Anzahl überschreiten
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

// Chunked Uploads mit bufio.Writer bearbeiten
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
				break // Body vollständig gelesen
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

// Upload-Aufgabe verarbeiten
func processUpload(task UploadTask) error {
	absFilename := task.AbsFilename
	fileStorePath := task.FileStorePath
	w := task.Writer
	r := task.Request

	startTime := time.Now()

	// Chunked Uploads bearbeiten, falls aktiviert
	if conf.ChunkingEnabled {
		err := handleChunkedUpload(absFilename, w, r)
		if err != nil {
			uploadDuration.Observe(time.Since(startTime).Seconds())
			return err
		}
		uploadDuration.Observe(time.Since(startTime).Seconds())
		return nil
	}

	// Dateiversionierung, falls aktiviert
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

	// Datei erstellen nach erfolgreicher HMAC-Validierung
	err := createFile(absFilename, fileStorePath, w, r)
	if err != nil {
		log.WithError(err).Error("Error creating file")
		uploadDuration.Observe(time.Since(startTime).Seconds())
		return err
	}

	uploadDuration.Observe(time.Since(startTime).Seconds())
	return nil
}

// Worker-Funktion zur Verarbeitung von Upload-Aufgaben
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
				// Optional: Retry-Logik hier implementieren
			}
			task.Done <- err
			close(task.Done)
		}
	}
}

// Datei für Upload erstellen mit buffered Writer
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
	buffer := make([]byte, 32*1024) // 32KB Buffer
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

// Download-Anfragen bearbeiten
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

	// Resumable Downloads bearbeiten, falls aktiviert
	if conf.ResumableDownloadsEnabled {
		handleResumableDownload(absFilename, w, r, fileInfo.Size())
		return
	}

	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))
		downloadsTotal.Inc()
		return
	} else {
		// Download-Dauer messen
		startTime := time.Now()
		http.ServeFile(w, r, absFilename)
		downloadDuration.Observe(time.Since(startTime).Seconds())
		downloadSizeBytes.Observe(float64(fileInfo.Size()))
		downloadsTotal.Inc()
		return
	}
}

// Dateiinfo mit Caching abrufen
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

// Resumable Downloads bearbeiten
func handleResumableDownload(absFilename string, w http.ResponseWriter, r *http.Request, fileSize int64) {
	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		// Wenn kein Range-Header, gesamte Datei servieren
		startTime := time.Now()
		http.ServeFile(w, r, absFilename)
		downloadDuration.Observe(time.Since(startTime).Seconds())
		downloadSizeBytes.Observe(float64(fileSize))
		downloadsTotal.Inc()
		return
	}

	// Range-Header parsen
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

	// End-Byte berechnen
	end := fileSize - 1
	if ranges[1] != "" {
		end, err = strconv.ParseInt(ranges[1], 10, 64)
		if err != nil || end >= fileSize {
			http.Error(w, "Invalid Range", http.StatusRequestedRangeNotSatisfiable)
			downloadErrorsTotal.Inc()
			return
		}
	}

	// Antwort-Header für Partial Content setzen
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, fileSize))
	w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusPartialContent)

	// Angeforderten Byte-Bereich servieren
	file, err := os.Open(absFilename)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		downloadErrorsTotal.Inc()
		return
	}
	defer file.Close()

	// Zum Start-Byte springen
	_, err = file.Seek(start, 0)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		downloadErrorsTotal.Inc()
		return
	}

	// Buffer erstellen und den angegebenen Bereich in den Response-Writer kopieren
	buffer := make([]byte, 32*1024) // 32KB Buffer
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

// Netzwerkereignisse bearbeiten
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
				// Beispiel: Prometheus Gauge aktualisieren oder Alarme auslösen
			}
			// Weitere Ereignistypen können hier behandelt werden
		}
	}
}

// Netzwerkänderungen überwachen
func monitorNetwork(ctx context.Context) {
	currentIP := getCurrentIPAddress() // Platzhalter für die aktuelle IP-Adresse

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

// Aktuelle IP-Adresse abrufen (Beispiel)
func getCurrentIPAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.WithError(err).Error("Failed to get network interfaces")
		return ""
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue // Interfaces überspringen, die nicht aktiv oder Loopback sind
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

// Graceful Shutdown einrichten
func setupGracefulShutdown(server *http.Server, cancel context.CancelFunc) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Info("Shutting down server...")

		// Deadline für das Shutdown setzen
		ctxShutdown, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(ctxShutdown); err != nil {
			log.WithError(err).Fatal("Server Shutdown Failed")
		}

		// Signale an andere Goroutinen senden, um sie zu stoppen
		cancel()

		// Upload-Queue und Netzwerkereignis-Kanal schließen
		close(uploadQueue)
		close(networkEvents)

		log.Info("Server gracefully stopped.")
		os.Exit(0)
	}()
}

// Worker-Pool initialisieren
func initializeWorkerPool(ctx context.Context) {
	for i := 0; i < 10; i++ { // MinWorkers = 10
		go uploadWorker(ctx, i)
	}
	// Dynamisches Skalieren kann hier implementiert werden, falls nötig
}

// Router mit Middleware einrichten
func setupRouter() http.Handler {
	mux := http.NewServeMux()
	subpath := path.Join("/", conf.UploadSubDir)
	subpath = strings.TrimRight(subpath, "/") + "/"
	mux.HandleFunc(subpath, handleRequest)
	if conf.MetricsEnabled {
		mux.Handle("/metrics", promhttp.Handler())
	}

	// Middleware anwenden
	handler := loggingMiddleware(corsMiddleware(mux))
	return handler
}

// Logging-Middleware
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestsTotal.WithLabelValues(r.Method, r.URL.Path).Inc()
		next.ServeHTTP(w, r)
	})
}

// CORS-Middleware
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

// Upload-Anfragen bearbeiten
func handleRequest(w http.ResponseWriter, r *http.Request) {
	log.WithFields(logrus.Fields{
		"method": r.Method,
		"url":    r.URL.String(),
		"remote": r.RemoteAddr,
	}).Info("Incoming request")

	// URL und Query-Parameter parsen
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

	// CORS-Header hinzufügen
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

// Upload-Anfragen mit Erweiterungen behandeln
func handleUpload(w http.ResponseWriter, r *http.Request, absFilename, fileStorePath string, a url.Values) {
	// Protokollversion basierend auf Query-Parametern bestimmen
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

	// HMAC initialisieren
	mac := hmac.New(sha256.New, []byte(conf.Secret))

	// MAC basierend auf protocolVersion berechnen
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

	// Übergebenen MAC aus Hex dekodieren
	providedMAC, err := hex.DecodeString(a.Get(protocolVersion))
	if err != nil {
		log.Warn("Invalid MAC encoding")
		http.Error(w, "Invalid MAC encoding", http.StatusForbidden)
		return
	}

	// HMAC validieren
	if !hmac.Equal(calculatedMAC, providedMAC) {
		log.Warn("Invalid MAC")
		http.Error(w, "Invalid MAC", http.StatusForbidden)
		return
	}

	// Dateierweiterung validieren
	if !isExtensionAllowed(fileStorePath) {
		log.WithFields(logrus.Fields{
			"filename":  fileStorePath,
			"extension": filepath.Ext(fileStorePath),
		}).Warn("Attempted upload with disallowed file extension")
		http.Error(w, "Disallowed file extension. Allowed extensions are: "+strings.Join(conf.AllowedExtensions, ", "), http.StatusForbidden)
		uploadErrorsTotal.Inc()
		return
	}

	// UploadTask mit einem Done-Kanal erstellen
	done := make(chan error)
	task := UploadTask{
		AbsFilename:   absFilename,
		FileStorePath: fileStorePath,
		Writer:        w,
		Request:       r,
		Done:          done,
	}

	// Task zur Upload-Queue hinzufügen
	select {
	case uploadQueue <- task:
		// Erfolgreich zur Queue hinzugefügt
		log.Debug("Upload task enqueued successfully")
	default:
		// Queue ist voll
		log.Warn("Upload queue is full. Rejecting upload")
		http.Error(w, "Server busy. Try again later.", http.StatusServiceUnavailable)
		uploadErrorsTotal.Inc()
		return
	}

	// Auf die Bearbeitung des Uploads warten
	err = <-done
	if err != nil {
		// Der Worker hat bereits eine entsprechende HTTP-Fehlermeldung gesendet
		return
	}

	// Upload war erfolgreich; Antwort wurde bereits vom Worker behandelt
}
