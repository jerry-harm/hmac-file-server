
# HMAC File Server

**A Secure, Scalable File Handling Server with HMAC Authentication**

The HMAC File Server provides a robust and secure platform for managing file uploads and downloads. It leverages HMAC authentication to ensure secure access and includes features like AES encryption, resumable uploads/downloads, virus scanning, file versioning, and monitoring through Prometheus metrics.

---

## Key Features

- **HMAC Authentication**:
  - Supports multiple authentication protocols (`v`, `v2`, `token`).
  - Ensures secure access to file operations.

- **File Handling**:
  - Resumable uploads and downloads with chunked processing.
  - File deduplication to save storage by using content checksums.
  - Automatic file versioning with configurable limits.

- **Encryption and Security**:
  - Data encryption using AES-CTR.
  - Integration with ClamAV for virus scanning.
  - Rate limiting, IP management, and Fail2Ban integration.

- **Monitoring**:
  - Prometheus metrics for detailed insights.
  - Tracks uploads, downloads, system performance, and errors.

- **Event-Driven Network Management**:
  - Monitors IP changes and handles network events asynchronously.

- **Graceful Shutdown**:
  - Cleans up resources and completes pending operations before shutting down.

---

## Requirements

1. **Software**:
   - Go 1.20+ installed on your machine.
   - ClamAV (optional, for virus scanning).
   - Redis (optional, for deduplication and token storage).

2. **Libraries**:
   - Installed automatically via `go mod tidy`.

---

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/hmac-file-server.git
cd hmac-file-server
```

### 2. Build the Server

```bash
go build -o hmac-file-server main.go
```

### 3. Configuration

Create a `config.toml` file based on the provided template. For example:

```toml
ListenPort = ":8080"
Secret = "your-secret-key"
StoreDir = "/path/to/storage"
MetricsEnabled = true
RedisEnabled = false
ClamAVEnabled = false
ChunkedUploadsEnabled = true
FileTTL = "30d"
```

### 4. Run the Server

```bash
./hmac-file-server
```

---

## Example Usage

### File Upload

```bash
curl -X PUT "http://localhost:8080/upload/myfile.txt?hmac=<HMAC>" --data-binary @myfile.txt
```

### File Download

```bash
curl -X GET "http://localhost:8080/upload/myfile.txt?hmac=<HMAC>"
```

### Metrics

Visit `http://localhost:9090/metrics` in your browser or scrape it using Prometheus.

---

## Configuration File

### Key Settings

- **Server Settings**:
  - `ListenPort`: Port to listen on (e.g., `":8080"`).
  - `StoreDir`: Directory for storing uploaded files.
  - `ChunkedUploadsEnabled`: Enable resumable/chunked uploads.

- **Security Settings**:
  - `Secret`: HMAC secret key for authentication.
  - `RateLimitingEnabled`: Enable rate limiting (e.g., `true`).
  - `MaxRequestsPerMinute`: Maximum allowed requests per minute.

- **Monitoring and Metrics**:
  - `MetricsEnabled`: Enable Prometheus metrics (e.g., `true`).
  - `MetricsPort`: Port for the Prometheus endpoint (e.g., `":9090"`).

- **Redis and ClamAV Integration**:
  - `RedisEnabled`: Enable Redis for deduplication and token storage.
  - `ClamAVEnabled`: Enable ClamAV for virus scanning.

For a complete list of settings, see `config.toml`.

---

## Features in Detail

1. **HMAC Authentication**:
   - Requests are authenticated using HMAC signatures.
   - Multiple protocol versions (`v`, `v2`, `token`) are supported.

2. **File Deduplication**:
   - Files are stored based on their checksum to avoid duplicates.
   - Requires Redis for managing deduplication metadata.

3. **Chunked Uploads**:
   - Large files can be uploaded in chunks, improving reliability for unstable connections.

4. **Resumable Downloads**:
   - Partial downloads are supported via HTTP `Range` headers.

5. **Prometheus Metrics**:
   - Provides metrics on system performance, uploads, downloads, errors, and queue lengths.

6. **Encryption**:
   - AES-CTR mode is used for stream encryption and decryption.

7. **ClamAV Scanning**:
   - Files can be scanned for viruses during upload.

8. **Fail2Ban Integration**:
   - Automatically blocks IPs with repeated failed requests.

---

## Development

### Running Tests

Add test cases for key functions like encryption, HMAC validation, and Redis interaction:

```bash
go test ./...
```

### Dependencies

Dependencies are managed via `go mod`. To update or clean dependencies:

```bash
go mod tidy
```

---

## Known Limitations

- **Integrity Protection**: AES-CTR provides encryption but does not protect against tampering. Use an HMAC tag for added integrity.
- **Performance**: Frequent Redis operations may be a bottleneck under heavy load. Optimize Redis usage if needed.

---

## Contributing

Contributions are welcome! Feel free to submit issues, suggestions, or pull requests.

---

## License

This project is licensed under the MIT License.

