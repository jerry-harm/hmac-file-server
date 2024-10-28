
# Prosody Configuration Guide for HMAC File Server

## Overview
This guide provides instructions to configure Prosody to work with the HMAC File Server, allowing secure file uploads and downloads with HMAC authentication.

## Prerequisites
1. **Prosody**: Ensure that Prosody is installed on your server.
2. **HMAC File Server**: Have the HMAC File Server installed and configured with valid HMAC authentication.

## Configuration Steps

### Step 1: Prosody Configuration File
Edit your Prosody configuration file, typically located at `/etc/prosody/prosody.cfg.lua`, to integrate with the HMAC File Server.

Add or modify the following settings:

```lua
-- Configure HTTP upload with HMAC authentication
Component "upload.yourdomain.com" "http_upload"
    http_upload_file_size_limit = 1024 * 1024 * 1024 -- 1GB limit
    http_upload_path = "/upload"
    http_external_url = "https://share.yourdomain.com/upload/"

-- Enable mod_http_upload_external for HMAC authentication
Component "upload.yourdomain.com" "http_upload_external"
    http_upload_external_base_url = "https://share.yourdomain.com/upload/"
    http_upload_external_secret = "YOUR_HMAC_SECRET"
    http_upload_external_host = "share.yourdomain.com"
    http_upload_external_protocol = "https"
    http_upload_external_port = 4443  -- Adjust if necessary, default is 443 for HTTPS
```

### Step 2: Adjust HMAC File Server Configuration
Make sure the HMAC File Server `config.toml` file is configured to match Prosody’s settings.

Key settings:
- `ListenPort`: Set to 8080 or another chosen port.
- `Secret`: Use the same HMAC secret as set in Prosody.
- `UploadSubDir`: Set to `/upload`.

```toml
# Example HMAC File Server config.toml
ListenPort = ":8080"
Secret = "YOUR_HMAC_SECRET"
StoreDir = "/path/to/storage"
UploadSubDir = "/upload"
```

### Step 3: Set Up NGINX as a Reverse Proxy
If using NGINX as a reverse proxy for the HMAC File Server, configure it to forward requests from Prosody to the server.

Example configuration:
```nginx
server {
    listen 443 ssl http2;
    server_name share.yourdomain.com;

    # SSL settings (adjust as necessary)
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location /upload/ {
        proxy_pass http://127.0.0.1:8080/upload/;
        proxy_buffering off;
        client_max_body_size 1G;
    }
}
```

### Step 4: Restart Services
After configuring both Prosody and NGINX, restart the services to apply changes.

```bash
sudo systemctl restart prosody
sudo systemctl restart nginx
```

## Testing
1. Connect a client (like Gajim or Conversations) to Prosody and test file uploads and downloads.
2. Monitor Prosody and NGINX logs to ensure successful uploads.

## Troubleshooting
- **Access Issues**: Check firewall settings and ensure ports 443 and 8080 are open.
- **HMAC Authentication Errors**: Confirm that the HMAC secrets in Prosody and the HMAC File Server match exactly.

## Conclusion
You have successfully configured Prosody to securely upload and download files using the HMAC File Server.

