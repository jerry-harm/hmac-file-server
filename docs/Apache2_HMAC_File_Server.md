
# Apache2 Configuration Guide for HMAC File Server

## Overview
This guide provides step-by-step instructions for configuring Apache2 as a reverse proxy for the HMAC File Server with SSL support using Let's Encrypt certificates. This setup includes optimizations for handling large file uploads and maintaining long client connections.

---

## Prerequisites
- **Apache2**: Ensure Apache2 is installed.
- **HMAC File Server**: Running on `localhost` at port `8080` (or your specified port).

---

## Step 1: Configure Apache2 as a Reverse Proxy

1. **Enable required Apache2 modules**:
   ```bash
   sudo a2enmod proxy proxy_http ssl headers
   ```

2. **Create a new configuration file** for the HMAC File Server reverse proxy:
   ```bash
   sudo nano /etc/apache2/sites-available/hmac-file-server.conf
   ```

3. **Add the following configuration** to set up SSL, proxy settings, and long upload timeout options. Replace `yourdomain.com` with your domain:

   ```apache
   <VirtualHost *:443>
       ServerName yourdomain.com

       # SSL configuration with Let's Encrypt
       SSLEngine on
       SSLCertificateFile /etc/letsencrypt/live/yourdomain.com/fullchain.pem
       SSLCertificateKeyFile /etc/letsencrypt/live/yourdomain.com/privkey.pem
       SSLCipherSuite HIGH:!aNULL:!MD5
       SSLProtocol All -SSLv2 -SSLv3
       SSLHonorCipherOrder on

       # Security Headers
       Header always set Strict-Transport-Security "max-age=31536000; includeSubdomains"
       Header always set X-Content-Type-Options "nosniff"
       Header always set X-Frame-Options "DENY"
       Header always set X-XSS-Protection "1; mode=block"
       Header always set Referrer-Policy "no-referrer-when-downgrade"
       Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

       # Proxy settings to HMAC File Server
       ProxyPass "/upload" "http://127.0.0.1:8080/upload"
       ProxyPassReverse "/upload" "http://127.0.0.1:8080/upload"

       # Increase timeout for large uploads
       ProxyTimeout 7200
       ProxyPreserveHost On
       ProxyPassReverseCookieDomain localhost yourdomain.com

       # Timeout settings for client connections
       Timeout 7200
       KeepAlive On
       MaxKeepAliveRequests 100
       KeepAliveTimeout 300

       # Error handling
       ErrorLog ${APACHE_LOG_DIR}/hmac_file_server_error.log
       CustomLog ${APACHE_LOG_DIR}/hmac_file_server_access.log combined

   </VirtualHost>
   ```

4. **Enable the new site configuration** and reload Apache2:
   ```bash
   sudo a2ensite hmac-file-server.conf
   sudo systemctl reload apache2
   ```

---

## Step 2: Test Your Setup

1. **Verify the SSL setup** by navigating to `https://yourdomain.com/upload`.
2. **Check Apache logs** for any errors:
   ```bash
   sudo tail -f /var/log/apache2/hmac_file_server_error.log
   ```

---

This configuration should now allow Apache2 to serve as a secure reverse proxy for your HMAC File Server, supporting large uploads with optimized timeouts and SSL encryption.

---

**End of Configuration**
