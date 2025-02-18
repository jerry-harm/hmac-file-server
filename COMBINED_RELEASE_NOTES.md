## HMAC File Server – Release v2.7

### What’s New
1. **Configurable Filenaming**  
   - Added support for `filenaming=None` to **skip** the default HMAC-based renaming.  
   - Allows users to keep the original filename instead of hashing, while preserving all HMAC authentication for security.

2. **Enhanced Logging**  
   - Improved log level usage (`info`, `warn`, `error`, `debug`) across the **login flow** and **file handling** operations.  
   - Added more structured fields (e.g., `method`, `remote`, `url`) for easier log analysis.  
   - Better security defaults to avoid exposing sensitive data in logs.

3. **Prometheus Metrics Adjustments**  
   - Refined counters, gauges, and histograms to cover **all** critical events (upload/download, dedup, ClamAV scanning).  
   - Ensured consistent increments for success/failure paths.  
   - Simplified registration to avoid double-registration issues.

4. **Deduplication Improvements**  
   - Confirmed that after moving a file to the dedup directory, a **hard link** is consistently created back to the original location.  
   - Logs now clearly indicate successful dedup steps and any errors.

5. **Worker Pool Enhancements**  
   - Better dynamic scaling logs (e.g., “Added worker. Total workers: X”).  
   - Ensures no duplicate or redundant worker creation.  
   - Additional metrics for worker adjustments and re-adjustments.

### Bug Fixes
- **Resolved “File Not Found” During GET**  
  - Clarified that when `filenaming=None`, the server does **not** rename files to HMAC paths, preventing mismatches between upload and download URLs.  
  - Fixed potential race conditions in dedup moving vs. linking.

- **Reduced Log Noise**  
  - Eliminated repetitive or misleading error messages around networking events.  
  - Improved clarity in ClamAV scanning logs to better distinguish scan failures vs. actual malware detections.

- Fixed dual stack IPv4 and IPv6 upload for improved reliability.

### Upgrade Notes
1. **Config File**:  
   - Check your `[server]` section for `filenaming`. If you previously relied on HMAC-based filenames, confirm whether you want to set `filenaming="HMAC"` explicitly.  
2. **Metrics**:  
   - If you track Prometheus data, your dashboards may need to be updated for any renamed metrics or new labels.  
3. **Logging**:  
   - Logging defaults remain at `info` level. Increase to `debug` only for troubleshooting to avoid excessive detail in production logs.

---

**Thank you** to everyone who contributed feedback and testing for this release! As always, please report any issues, and we welcome suggestions to further improve the HMAC File Server. Enjoy the streamlined filenames, more comprehensive logging, and robust Prometheus metrics!
