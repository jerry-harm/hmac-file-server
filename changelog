
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [2.4.1] - 2025-03-10
### Changed
- **Configuration:** Updated `globalextensions` in `config.toml` to `["*"]`, allowing all file types globally for uploads. This change simplifies the configuration by removing the need to specify individual file extensions.

## [2.4.0] - 2025-02-20
### Added
- **Pre-Caching Support:** Introduced pre-caching of storage paths to improve access speeds.
- **ISO Container Management:** Added functionality to create and mount ISO containers for specialized storage needs.
- **Thumbnail Concurrency Parameter:** Users can now set the level of concurrency for thumbnail generation to optimize performance.

### Changed
- **Configuration Options:** Updated `config.toml` to include new settings for pre-caching and ISO management.
- **Documentation:** Enhanced `README.MD` with detailed instructions on new features and best practices.

### Fixed
- **Bug Fixes:** Resolved minor issues related to file versioning and deduplication processes.

## [2.3.1] - 2025-01-15
### Changed
- **Configuration:** Updated `globalextensions` in `config.toml` to `["*"]`, allowing all file types globally for uploads. This change simplifies the configuration by removing the need to specify individual file extensions.

## [2.3.0] - 2024-12-28
### Changed
- **Server:** Replaced the hardcoded temporary upload directory `/tmp/uploads` with a configurable `TempPath` parameter in `config.toml`. Ensure to set `tempPath` in your configuration file accordingly.

## [2.2.2] - 2024-12-27
### Bug Fixes
- Resolved issue where temporary `.tmp` files caused "Unsupported file type" warnings by adjusting MIME type detection to use the final file extension.

### Enhancements
- Improved logging for file extension and MIME type during uploads.

## [2.2.1] - 2024-12-27
### Enhancements
- Added detailed logging for file extensions and MIME types during file uploads to assist in diagnosing unsupported file type issues.

### Configuration
- Updated `config.toml` to ensure necessary file extensions are allowed for uploads.