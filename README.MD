# HMAC File Server
A secure file server with HMAC authentication and configurable features.

// ...existing code...

## Features

- **HMAC Authentication:** Secure file uploads and downloads with HMAC tokens.
- **File Versioning:** Enable versioning for uploaded files with configurable retention.
- **Chunked and Resumable Uploads:** Handle large files efficiently with support for resumable and chunked uploads.
- **Deduplication:** Automatically remove duplicate files based on hashing for storage efficiency.
- **ClamAV Scanning:** Optional virus scanning for uploaded files.
- **Prometheus Metrics:** Monitor system and application-level metrics.
- **Redis Integration:** Use Redis for caching or storing application states.
- **File Expiration:** Automatically delete files after a specified TTL.
- **Graceful Shutdown:** Handles signals and ensures proper cleanup.
- **Auto-Adjust Worker Scaling:** Dynamically optimize worker threads based on system resources when enabled.
// Thumbnail support was removed in version 2.5

// ...existing code...

## Configuration

// ...existing code...

// Removed Thumbnail Creation section

// ...existing code...

## Additional Features

// ...existing features...

// Removed Thumbnail Creation details

// ...existing code...
