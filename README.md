
# HMAC File Server

## Overview
HMAC File Server is a secure file server designed to handle file uploads and downloads using HMAC-based authentication for added security. 
It includes features such as resumable uploads/downloads, versioning, and optional Redis and Prometheus integration.

## Version
**Current Version:** v2.0.1

## Features
- Secure HMAC authentication for uploads and downloads
- Resumable uploads and downloads
- File versioning and expiration
- Prometheus metrics for monitoring
- Redis support for caching
- Optional Fallback to PostgreSQL or MySQL

## Configuration
Configuration is handled via a `config.toml` file located in the server directory. The main settings include:

- `ListenPort`: Port for the file server to listen on.
- `Secret`: HMAC secret for securing uploads.
- `StoreDir`: Directory for storing uploaded files.
- `ResumableUploadsEnabled`: Enable or disable resumable uploads.
- And more...

---

## Running the Server
After configuring your `config.toml`, start the server using the following command:

```bash
./hmac-file-server -config ./config.toml
```

## Contributing
We welcome contributions to improve this project. Feel free to open issues or submit pull requests.

