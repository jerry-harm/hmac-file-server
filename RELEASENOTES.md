
# HMAC File Server - Release Notes

## Version 1.0.4 - October 19, 2024

### Enhancements:
- Added flexible checksum validation using a configurable header `X-Checksum`.
- Introduced auto-deletion based on file age and total storage size.
- Improved logging for file operations, including file versioning and checksum mismatch reporting.
- Added retention policy that checks for files older than a specified duration (e.g., 30d, 1y).
- Auto-deletion logic improved to correctly handle cutoff times for file age.
- Implemented Prometheus metrics for tracking file uploads, errors, and performance.

### Bug Fixes:
- Fixed an issue where files were incorrectly selected for deletion due to faulty age comparisons.
- Improved directory creation and handling for file uploads.
- Enhanced support for multiple cores by allowing configuration via `NumCores`.

### Configuration Updates:
- New options for `ChecksumVerification`, `ChecksumHeader`, and `ChecksumAlgorithm` to control file integrity validation.
- New retention policy settings: `MaxRetentionSize` and `MaxRetentionTime`.
- Added timeout settings for better control over idle connections and request handling.
