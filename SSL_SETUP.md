# SSL/TLS Configuration Guide

WakeStation supports HTTPS without requiring a reverse proxy. You can use either self-signed certificates (for testing/internal networks) or Let's Encrypt certificates (for production).

## Quick Start

### Option 1: Self-Signed Certificate (Development/Testing)

**Generate certificate:**
```bash
./generate_ssl_cert.sh
```

**Update config.py:**
```python
ENABLE_SSL = True
SSL_CERTFILE = "/opt/wol/ssl/cert.pem"
SSL_KEYFILE = "/opt/wol/ssl/key.pem"
SSL_CA_CERTS = None
```

### Option 2: Internal CA Certificate

If you have an internal Certificate Authority (like your `cacert.pem`):

**Update config.py:**
```python
ENABLE_SSL = True
SSL_CERTFILE = "/path/to/your-signed-cert.pem"
SSL_KEYFILE = "/path/to/your-private-key.pem"
SSL_CA_CERTS = "/path/to/cacert.pem"  # Your internal CA
```

### Option 3: Let's Encrypt (Production)

**Install certbot:**
```bash
# Debian/Ubuntu
sudo apt install certbot

# RHEL/CentOS
sudo yum install certbot
```

**Generate certificate:**
```bash
sudo certbot certonly --standalone -d your-domain.com
```

**Update config.py:**
```python
ENABLE_SSL = True
SSL_CERTFILE = "/etc/letsencrypt/live/your-domain.com/fullchain.pem"
SSL_KEYFILE = "/etc/letsencrypt/live/your-domain.com/privkey.pem"
SSL_CA_CERTS = None  # Let's Encrypt uses public CAs
```

**Set up auto-renewal:**
```bash
# Test renewal
sudo certbot renew --dry-run

# Add cron job for auto-renewal
sudo crontab -e
# Add: 0 3 * * * certbot renew --quiet --post-hook "systemctl restart wakestation"
```

## Certificate File Formats

WakeStation expects PEM-formatted certificates:

- **SSL_CERTFILE**: Certificate file (`.pem`, `.crt`)
  - For Let's Encrypt: Use `fullchain.pem` (includes intermediate certificates)
  - For self-signed/internal CA: Use your certificate file

- **SSL_KEYFILE**: Private key file (`.pem`, `.key`)
  - Must be unencrypted (no passphrase)
  - Keep this file secure (permissions: 600)

- **SSL_CA_CERTS**: (Optional) CA certificate bundle
  - Only needed for internal/self-signed certificates
  - Not needed for Let's Encrypt or public CAs

## File Permissions

Ensure proper permissions for security:

```bash
# Certificate (readable by all, needed by WakeStation)
chmod 644 /path/to/cert.pem

# Private key (readable only by owner)
chmod 600 /path/to/key.pem
chown wakestation:wakestation /path/to/key.pem
```

## Systemd Service Configuration

If using Let's Encrypt with systemd, update `/etc/systemd/system/wakestation.service`:

```ini
[Service]
# Allow reading Let's Encrypt certificates
SupplementaryGroups=ssl-cert
```

Then reload and restart:
```bash
sudo systemctl daemon-reload
sudo systemctl restart wakestation
```

## Troubleshooting

### Certificate not found
```
ERROR SSL certificate file not found: /path/to/cert.pem
```
**Solution:** Check the path in `config.py` and verify file exists

### Permission denied
```
PermissionError: [Errno 13] Permission denied: '/etc/letsencrypt/live/...'
```
**Solution:** Run as root or add user to `ssl-cert` group:
```bash
sudo usermod -a -G ssl-cert wakestation
```

### Browser security warning (self-signed)
```
NET::ERR_CERT_AUTHORITY_INVALID
```
**Solution:** This is expected for self-signed certificates. Options:
- Accept the warning (for testing)
- Import your `cacert.pem` into browser trust store
- Use Let's Encrypt for production

### Mixed content warnings
```
Mixed Content: The page was loaded over HTTPS, but requested an insecure resource
```
**Solution:** All internal links already use relative paths. External resources (jQuery, crypto-js) are loaded via HTTPS CDN.

## Security Notes

1. **Cookie Security:** When `ENABLE_SSL = True`, cookies are automatically set to `Secure` flag
2. **HSTS:** Consider adding HSTS headers in production for enhanced security
3. **Certificate Renewal:** Let's Encrypt certificates expire after 90 days - set up auto-renewal
4. **Private Key:** Never commit `key.pem` to git. Keep it secure with 600 permissions.

## Verification

After enabling SSL, verify the setup:

```bash
# Check certificate
openssl s_client -connect 10.0.1.13:8889 -showcerts

# Check service
curl -k https://10.0.1.13:8889/api/health

# View in browser
https://10.0.1.13:8889/
```

## Reverting to HTTP

To disable SSL and use HTTP:

**Update config.py:**
```python
ENABLE_SSL = False
```

Restart the service. The application will fall back to HTTP.
