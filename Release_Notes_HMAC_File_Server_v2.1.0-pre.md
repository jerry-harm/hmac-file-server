
# Release Notes for HMAC File Server v2.1.0-pre
**Release Date:** November 18, 2024

---

## Overview

Version 2.1.0-pre introduces advanced security, file handling, and cross-platform improvements. This pre-release focuses on enhancing ARM64 compatibility, integrating AES encryption for stream data, improving logging and metrics, and resolving key issues identified in previous versions.

---

## New Features

### **1. AES Encryption for Streams**
- **EncryptStream/DecryptStream Functions**:
  - Added AES-CTR-based stream encryption and decryption, providing secure file handling during transmission.
  - Ensures confidentiality without impacting system performance.
  
### **2. MIME Detection Enhancements**
- Integrated MIME detection using `magicmime` for accurate file type identification.
- Alternative fallback: Introduced `h2non/filetype` for environments where `magicmime` is unavailable or problematic (e.g., ARM64).

### **3. Improved Cross-Platform Support**
- Full support for cross-compilation, including AMD64 and ARM64 platforms.
- Addressed compatibility issues with `libmagic` for ARM64 through streamlined dependency management.

### **4. Logging Improvements**
- New logging configuration settings:
  - Enable or disable logging (`LoggingEnabled`).
  - Adjustable log levels (`debug`, `info`, `warn`, `error`).
  - Customizable log file paths.

### **5. Enhanced ClamAV Integration**
- **ClamAV Workers**:
  - Configurable number of scan workers via `NumScanWorkers` in `config.toml`.
  - Improved performance and reduced scanning delays for large-scale deployments.
- **Sample Configuration**:
  ```toml
  ClamAVEnabled            = true
  NumScanWorkers           = 10
  ClamAVSocket             = "/var/run/clamav/clamd.ctl" # Use UNIX socket; alternatively use TCP
  ```

### **6. Redis and Deduplication**
- Optimized Redis-based file deduplication for faster checksum verification and metadata handling.
- Improved resilience against Redis connection failures.

---

## Bug Fixes

### **1. ARM64 Compatibility**
- Resolved build constraints for ARM64 environments.
- Ensured seamless `magicmime` library usage with appropriate CGO and cross-compilation flags.

### **2. Temporary File Handling**
- Fixed issues with temporary file renaming, especially under restrictive file permissions.

### **3. File Versioning**
- Corrected file version cleanup logic to prevent unintended deletions when `MaxVersions` is exceeded.

### **4. Logging Reliability**
- Addressed intermittent logging failures in high-concurrency scenarios.

---

## Known Issues

### **1. ClamAV Scanning Delays**
- In some cases, ClamAV scanning may experience latency with large file sizes. Investigation is ongoing for further optimization.

### **2. ARM64 Dependency Setup**
- Cross-compilation to ARM64 requires manual installation of specific libraries (e.g., `libmagic-dev:arm64`).

---

## Configuration Additions

### **Logging Configuration**
```toml
# Logging Configuration
LoggingEnabled           = true                                 # Enable or disable logging
LogLevel                 = "info"                               # Logging level: "debug", "info", "warn", "error"
LogFile                  = "./logs/hmac-file-server.log"        # Log file path
```

### **File Encryption and Stream Handling**
```go
// EncryptStream Example Usage
key := []byte("32-byte-long-key-for-AES-encryption!")
err := EncryptStream(key, inputReader, outputWriter)
```

---

## Upgrade Instructions

1. **Backup**: Backup your current system configuration and data.
2. **Download**: Obtain the `hmac-file-server_2.1.0-pre` binaries for your platform (e.g., AMD64, ARM64).
3. **Update Configuration**: Update `config.toml` with new settings as needed.
4. **Restart**: Restart the server after applying the update.

---

## Feedback

Your feedback is vital in refining this release. Please report any issues or suggestions to our support team at [support@uuxo.net](mailto:support@uuxo.net).

---

Thank you for your support in shaping the future of the HMAC File Server!
