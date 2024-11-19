
# Integrating ClamAV with HMAC File Server

This guide explains how to configure and integrate ClamAV, an antivirus engine, with the HMAC file server to enable file scanning for malware.

---

## Prerequisites

- **ClamAV** installed and running on the system.
- Proper permissions for the HMAC file server to access ClamAV’s socket or TCP interface.
- The HMAC file server configuration file (e.g., `config.toml`).

---

## Step 1: Install and Configure ClamAV

### Install ClamAV
For most Linux distributions, use the package manager to install ClamAV:
```bash
sudo apt update
sudo apt install clamav clamav-daemon
```

### Update Virus Definitions
Ensure ClamAV’s virus database is up to date:
```bash
sudo freshclam
```

### Configure ClamAV
Edit the ClamAV configuration file (typically located at `/etc/clamav/clamd.conf`) to suit your requirements:
- Enable file scanning:
  ```plaintext
  ScanFile true
  ScanArchive true
  ```
- Set file size limits (adjust as necessary):
  ```plaintext
  MaxFileSize 500M
  MaxScanSize 500M
  ```
- Choose the socket type (UNIX or TCP):
  - **UNIX Socket**:
    ```plaintext
    LocalSocket /var/run/clamav/clamd.ctl
    ```
  - **TCP Socket**:
    ```plaintext
    TCPSocket 3310
    TCPAddr 127.0.0.1
    ```

Restart the ClamAV service to apply changes:
```bash
sudo systemctl restart clamav-daemon
```

---

## Step 2: Configure HMAC File Server

### Enable ClamAV in the HMAC Server Configuration
Edit the `config.toml` file to enable and configure ClamAV:
```toml
# Enable ClamAV integration
ClamAVEnabled = true

# Specify the ClamAV socket (use one of the following)
ClamAVSocket = "/var/run/clamav/clamd.ctl"  # UNIX socket
# ClamAVSocket = "127.0.0.1:3310"           # TCP socket

# Number of workers for scanning
NumScanWorkers = 5
```

### Adjust File Permissions
Ensure the HMAC server user has read/write access to the ClamAV socket:
```bash
sudo chmod 777 /var/run/clamav/clamd.ctl
```

---

## Step 3: Test the Integration

### Verify ClamAV Connectivity
Start the HMAC file server and verify ClamAV initialization in the logs:
```bash
./hmac-file-server
```

Logs should indicate successful ClamAV initialization:
```plaintext
INFO: ClamAV initialized.
```

### Test File Scanning
Upload a file to the server and check the logs for scanning results:
- **Clean File**:
  ```plaintext
  INFO: Scan succeeded.
  ```
- **Infected File**:
  ```plaintext
  ERROR: Virus detected: <virus-name>
  ```

---

## Troubleshooting

### Common Issues
1. **Permission Denied**:
   Ensure the HMAC server user has access to ClamAV's socket or TCP port.
2. **ClamAV Service Not Running**:
   Start or restart the ClamAV daemon:
   ```bash
   sudo systemctl start clamav-daemon
   ```
3. **Scan Errors**:
   Check ClamAV logs for detailed error messages:
   ```bash
   tail -f /var/log/clamav/clamd.log
   ```

---

## Notes

- Consider setting up a monitoring system for ClamAV to ensure it remains operational.
- Keep the virus definitions up to date using `freshclam`.

--- 

By following these steps, your HMAC file server should be successfully integrated with ClamAV for enhanced file security.
