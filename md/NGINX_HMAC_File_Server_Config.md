
# NGINX Configuration for HMAC File Server

This guide provides an optimized NGINX configuration to handle large file uploads and enable secure, resumable file transfer with the HMAC File Server.

---

## 1. Basic Configuration

Ensure that the NGINX server block listens on port 443 for SSL connections and uses Let's Encrypt certificates for encryption.

```nginx
server {
    listen 443 ssl http2;
    server_name share.example.com;

    # SSL settings with Let's Encrypt
    ssl_certificate /etc/letsencrypt/live/share.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/share.example.com/privkey.pem;
    ssl_dhparam /etc/ssl/certs/dhparam.pem;
```

## 2. Security Headers

To enhance security, add strict transport security and disable features that can pose a risk if exposed.

```nginx
    add_header Strict-Transport-Security "max-age=31536000; includeSubdomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

## 3. Upload Location Settings

Configure the location block to manage CORS settings, buffering, and timeouts, and enable proxy settings for connecting to the HMAC File Server.

```nginx
    location / {
        # CORS settings
        if ($request_method = OPTIONS) {
            add_header Access-Control-Allow-Origin '*';
            add_header Access-Control-Allow-Methods 'PUT, GET, OPTIONS, HEAD';
            add_header Access-Control-Allow-Headers 'Authorization, Content-Type, X-Requested-With';
            add_header Access-Control-Allow-Credentials 'true';
            add_header Content-Length 0;
            add_header Content-Type text/plain;
            return 200;
        }

        # Proxy settings
        proxy_pass http://127.0.0.1:8080/upload/;

        # Disable buffering for real-time processing
        proxy_request_buffering off;
        proxy_buffering off;

        # Timeout settings
        proxy_connect_timeout 2h;
        proxy_send_timeout    2h;
        proxy_read_timeout    2h;
        send_timeout          2h;
        client_body_timeout   2h;
        keepalive_timeout     2h;

        # Error handling
        proxy_intercept_errors on;
        error_page 403 /custom_403.html;
    }

    # Serve the custom error page
    location = /custom_403.html {
        root /var/www/share;
    }

    # Logging for debugging
    error_log /var/log/nginx/upload_errors.log warn;
}
```

---

## 4. Logging and Error Pages

Configure logging and custom error pages to help troubleshoot and handle unauthorized access attempts effectively.

Place your custom error page at `/var/www/share/custom_403.html` or adjust the path as needed.

---

This configuration supports resumable uploads, secure SSL connections with Let's Encrypt, and ensures long timeout settings for large file transfers.
