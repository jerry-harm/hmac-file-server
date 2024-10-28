
# Ejabberd Configuration Guide for HMAC File Server Integration

## Prerequisites
- **Ejabberd** installed and running.
- **HMAC File Server** configured with a known `Secret` and reachable by the Ejabberd server.
- **mod_http_upload** enabled on Ejabberd for handling file uploads.

---

## Step 1: Enable `mod_http_upload`

Ensure that `mod_http_upload` is enabled in the Ejabberd configuration file (`ejabberd.yml`):

```yaml
modules:
  mod_http_upload:
    put_url: https://your-domain.com/upload
    get_url: https://your-domain.com/upload
    max_size: 1073741824 # Set your upload limit here (in bytes, e.g., 1GB)
```

Replace `your-domain.com` with your domain where the HMAC File Server is hosted.

## Step 2: Configure `mod_http_upload` to Use HMAC Authentication

Modify the `mod_http_upload` configuration to include HMAC-based URL generation by creating a custom upload policy. Update the upload configuration in `ejabberd.yml`:

```yaml
modules:
  mod_http_upload:
    put_url: https://your-domain.com/upload
    get_url: https://your-domain.com/upload
    docroot: "/path/to/uploaded/files"
    secret: "your-hmac-secret"  # This secret should match the HMAC File Server configuration
    max_size: 1048576000  # Adjust file size as needed
    custom_headers:
      X-Requested-With: XMLHttpRequest
    hmac_enabled: true
    hmac_secret: "your-hmac-secret"
```

## Step 3: Set Up Custom Headers and Security Options

To enhance security and ensure HMAC-based authentication, add custom headers to requests, if your HMAC server configuration supports it.

```yaml
custom_headers:
  X-Requested-With: XMLHttpRequest
  Content-Type: application/octet-stream
```

## Step 4: Restart Ejabberd

After updating `ejabberd.yml`, restart Ejabberd to apply the changes.

```bash
sudo systemctl restart ejabberd
```

## Step 5: Verify Configuration

To confirm the integration is successful:

1. **Test a file upload** using an XMPP client that supports HTTP upload (such as Conversations or Gajim).
2. **Check Ejabberd logs** for any errors related to `mod_http_upload` or file transfers.
3. **Inspect HMAC File Server logs** to verify that authenticated requests are being processed.

## Important Considerations

- **SSL Certificates:** Ensure SSL is correctly configured on both Ejabberd and the HMAC File Server for secure communication.
- **File Size Limitations:** The `max_size` parameter in `mod_http_upload` should match or be less than the limit set on the HMAC File Server.

---
