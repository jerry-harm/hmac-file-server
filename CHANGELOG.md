
# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

- Initial creation of a comprehensive changelog.

---

## [2.6-Stable] - 2025-12-01
### Added
- Deduplication support (removes duplicate files).
- ISO Container management.
- Dynamic worker scaling based on CPU & memory.
- PreCaching feature for faster file access.

### Changed
- Worker pool scaling strategies for better performance.
- Enhanced logging with rotating logs using lumberjack.

### Fixed
- Temporary file handling issues causing "Unsupported file type" warnings.
- MIME type checks for file extension mismatches.

---

## [2.5] - 2025-09-15
### Added
- Redis caching integration for file metadata.
- ClamAV scanning for virus detection before finalizing uploads.

### Changed
- Extended the default chunk size for chunked uploads.
- Updated official documentation links.

### Fixed
- Edge case with versioning causing file rename conflicts.

---

## [2.0] - 2025-06-01
### Added
- Chunked file uploads and downloads.
- Resumable upload support with partial file retention.

### Changed
- Moved configuration management to Viper.
- Default Prometheus metrics for tracking memory & CPU usage.

### Fixed
- Race conditions in file locking under heavy concurrency.

---

## [1.0] - 2025-01-01
### Added
- Initial release with HMAC-based authentication.
- Basic file upload/download endpoints.
- Logging and fundamental configuration using .toml files.