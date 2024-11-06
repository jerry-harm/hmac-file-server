# Security settings
RateLimitingEnabled = true
MaxRequestsPerMinute = 60
RateLimitInterval = "1m"
BlockedUserAgents = ["BadBot", "EvilCrawler"]

# Fail2b
Enable = true                                                   # Enable or disable Fail2Ban integration
Jail = "hmac-auth"                                              # Name of the jail to use in Fail2Ban
BlockCommand = "/usr/bin/fail2ban-client set hmac-auth <IP>" # Command to block an IP
UnblockCommand = "/usr/bin/fail2ban-client set hmac-auth unban <IP>" # Command to unblock an IP
MaxRetries = 3                                                  # Number of failed attempts before banning
BanTime = "3600s"                                               # Duration for which the IP should be banned (1 hour in this case)

# IP Management settings (optional)
EnableIPManagement = false
AllowedIPs = ["0.0.0.0/0"]
IPCheckInterval = "60s"
