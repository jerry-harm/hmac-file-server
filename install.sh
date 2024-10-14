#!/bin/bash

# Create a system user for hmac-file-server without login access
echo "Creating system user for hmac-file-server..."
sudo useradd -r -d /home/hmac-file-server -s /usr/sbin/nologin hmac-file-server

# Create the home directory for the hmac-file-server user
echo "Creating home directory for hmac-file-server at /home/hmac-file-server..."
sudo mkdir -p /home/hmac-file-server

# Change ownership of the directory to hmac-file-server user
echo "Setting ownership of /home/hmac-file-server to hmac-file-server user..."
sudo chown hmac-file-server:hmac-file-server /home/hmac-file-server

# Create systemd service file for hmac-file-server
echo "Creating systemd service file for hmac-file-server..."
sudo bash -c 'cat <<EOL > /etc/systemd/system/hmac-file-server.service
[Unit]
Description=HMAC File Server - Secure File Handling Server
After=network.target

[Service]
ExecStart=/home/hmac-file-server/hmac-file-server --config=/home/hmac-file-server/config.toml
WorkingDirectory=/home/hmac-file-server
Restart=on-failure
User=hmac-file-server
Group=hmac-file-server
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOL'

# Set proper permissions for the systemd service file
echo "Setting permissions for the systemd service file..."
sudo chmod 644 /etc/systemd/system/hmac-file-server.service

# Reload systemd to apply the new service
echo "Reloading systemd..."
sudo systemctl daemon-reload

# Enable the hmac-file-server service to start on boot
echo "Enabling hmac-file-server service..."
sudo systemctl enable hmac-file-server.service

# Start the hmac-file-server service
echo "Starting hmac-file-server service..."
sudo systemctl start hmac-file-server.service

# Check service status
echo "Checking hmac-file-server service status..."
sudo systemctl status hmac-file-server.service
