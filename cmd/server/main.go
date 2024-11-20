package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

var (
	conf         Config
	redisClient  *redis.Client
	sessionMutex sync.Mutex
	log          = logrus.New()

	// Prometheus metrics
	uploadsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "hmac",
		Name:      "uploads_total",
		Help:      "Total number of uploads",
	})
)

// Config holds the server configuration.
type Config struct {
	ListenIP               string `toml:"ListenIP"`
	ListenPort             string `toml:"ListenPort"`
	Secret                 string `toml:"Secret"`
	StoreDir               string `toml:"StoreDir"`
	RedisEnabled           bool   `toml:"RedisEnabled"`
	RedisAddr              string `toml:"RedisAddr"`
	SessionRefreshInterval string `toml:"SessionRefreshInterval"`
	EncryptionMethod       string `toml:"EncryptionMethod"` // "hmac" or "aes"
	EncryptionKey          string `toml:"EncryptionKey"`
	UnixSocket             bool   `toml:"UnixSocket"`
	// Add other configuration fields as needed...
	// Example:
	// TLS struct { ... } `toml:"TLS"`
}

func main() {
	// Load configuration
	if err := readConfig("./config.toml", &conf); err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	setupLogging()
	initMetrics()

	if conf.RedisEnabled {
		if err := initRedis(); err != nil {
			log.Fatalf("Failed to initialize Redis: %v", err)
		}
	}

	// Start session refresh routine
	startSessionRefresher()

	// Initialize HTTP handlers
	router := setupRouter()

	// Configure timeouts
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
		Addr:         net.JoinHostPort(conf.ListenIP, conf.ListenPort),
		Handler:      router,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	// Graceful shutdown
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		<-c
		log.Info("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	log.Infof("Starting server on %s:%s", conf.ListenIP, conf.ListenPort)
	if conf.UnixSocket {
		listener, err := net.Listen("unix", conf.ListenPort)
		if err != nil {
			log.WithError(err).Fatal("Unix socket listen failed.")
		}
		defer listener.Close()
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("Server failed.")
		}
	} else {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("Server failed.")
		}
	}
}

// readConfig reads and parses the TOML configuration file.
func readConfig(path string, conf *Config) error {
	if _, err := toml.DecodeFile(path, conf); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults if necessary
	if conf.ListenIP == "" {
		conf.ListenIP = "127.0.0.1" // Default to localhost
	}
	if conf.ListenPort == "" {
		conf.ListenPort = "8080" // Default port without colon
	}
	if conf.StoreDir == "" {
		conf.StoreDir = "/tmp/store"
	}
	if conf.Secret == "" {
		conf.Secret = "defaultsecret"
	}
	if conf.SessionRefreshInterval == "" {
		conf.SessionRefreshInterval = "30m"
	}
	if conf.EncryptionMethod == "" {
		conf.EncryptionMethod = "aes"
	}
	if conf.EncryptionKey == "" {
		conf.EncryptionKey = "defaultencryptionkey123"
	}
	// Add other default settings as needed...

	log.WithFields(logrus.Fields{
		"ListenIP":         conf.ListenIP,
		"ListenPort":       conf.ListenPort,
		"UnixSocket":       conf.UnixSocket,
		"StoreDir":         conf.StoreDir,
		"LoggingEnabled":   conf.LoggingEnabled,
		"LogLevel":         conf.LogLevel,
		"MetricsEnabled":   conf.MetricsEnabled,
		"FileTTL":          conf.FileTTL,
		"EncryptionMethod": conf.EncryptionMethod,
	}).Info("Configuration loaded successfully")

	return nil
}

// setupLogging configures the logging based on the configuration.
func setupLogging() {
	level, err := logrus.ParseLevel(conf.LogLevel)
	if err != nil {
		log.SetLevel(logrus.InfoLevel)
		log.Warnf("Invalid log level '%s', defaulting to 'info'", conf.LogLevel)
	} else {
		log.SetLevel(level)
	}

	if conf.LoggingEnabled && conf.LogFile != "" {
		file, err := os.OpenFile(conf.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file %s: %v", conf.LogFile, err)
		}
		log.SetOutput(file)
	} else {
		log.SetOutput(os.Stdout)
	}

	log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	log.Info("Logging initialized.")
}

// initRedis initializes the Redis client.
func initRedis() error {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     conf.RedisAddr,
		Password: conf.RedisPassword,
		DB:       conf.RedisDBIndex,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := redisClient.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}

	log.Info("Connected to Redis.")
	return nil
}

// initMetrics initializes Prometheus metrics.
func initMetrics() {
	prometheus.MustRegister(uploadsTotal)
	// Register other metrics as needed...
}

// startSessionRefresher starts a goroutine to refresh sessions periodically.
func startSessionRefresher() {
	duration, err := time.ParseDuration(conf.SessionRefreshInterval)
	if err != nil {
		log.WithError(err).Error("Invalid session refresh interval")
		return
	}

	go func() {
		ticker := time.NewTicker(duration)
		defer ticker.Stop()

		for range ticker.C {
			refreshSessions()
		}
	}()
}

// refreshSessions refreshes network sessions like Redis connections.
func refreshSessions() {
	log.Info("Refreshing network sessions...")
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	if conf.RedisEnabled {
		if redisClient != nil {
			if err := redisClient.Close(); err != nil {
				log.WithError(err).Error("Failed to close Redis client")
			}
		}
		if err := initRedis(); err != nil {
			log.WithError(err).Error("Failed to reinitialize Redis client")
		} else {
			log.Info("Redis client reinitialized successfully")
		}
	}

	// Add any additional session refresh logic here...
}

// setupRouter sets up the HTTP routes.
func setupRouter() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/upload", handleUpload)
	// Add other handlers as needed...
	return mux
}

// handleUpload handles file upload requests.
func handleUpload(w http.ResponseWriter, r *http.Request) {
	// Validate HMAC
	if !validateHMAC(r) {
		http.Error(w, "Invalid HMAC", http.StatusForbidden)
		return
	}

	// Save file
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "Filename is required", http.StatusBadRequest)
		return
	}
	destPath := filepath.Join(conf.StoreDir, filepath.Base(filename))

	if err := saveFile(r.Body, destPath); err != nil {
		log.WithError(err).Error("Failed to save file")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	uploadsTotal.Inc()
	w.WriteHeader(http.StatusCreated)
}

// validateHMAC validates the HMAC signature of the request.
func validateHMAC(r *http.Request) bool {
	message := r.URL.Path
	providedMAC := r.Header.Get("X-HMAC")
	if providedMAC == "" {
		return false
	}

	mac, err := hex.DecodeString(providedMAC)
	if err != nil {
		return false
	}

	h := hmac.New(sha256.New, []byte(conf.Secret))
	h.Write([]byte(message))
	expectedMAC := h.Sum(nil)

	return hmac.Equal(mac, expectedMAC)
}

// saveFile saves the uploaded file, optionally encrypting it.
func saveFile(src io.Reader, destPath string) error {
	// Create the directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}

	file, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer file.Close()

	var writer io.Writer = file

	// Encrypt if enabled
	if strings.ToLower(conf.EncryptionMethod) == "aes" && conf.EncryptionKey != "" {
		block, err := aes.NewCipher([]byte(conf.EncryptionKey))
		if err != nil {
			return err
		}
		iv := make([]byte, aes.BlockSize)
		if _, err := rand.Read(iv); err != nil {
			return err
		}
		// Write IV to the beginning of the file
		if _, err := file.Write(iv); err != nil {
			return err
		}
		stream := cipher.NewCTR(block, iv)
		writer = &cipher.StreamWriter{S: stream, W: file}
	}

	if _, err := io.Copy(writer, src); err != nil {
		return err
	}

	return nil
}

// Example function: setupGracefulShutdown is included within main via a goroutine
