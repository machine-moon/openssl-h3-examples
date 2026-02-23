# mod_http3 Configuration Guide

This document provides comprehensive configuration instructions for mod_http3, an Apache HTTP Server module that adds HTTP/3 support using OpenSSL and nghttp3.

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Configuration Directives](#configuration-directives)
- [Basic Configuration](#basic-configuration)
- [VirtualHost Configuration](#virtualhost-configuration)
- [Configuration Validation](#configuration-validation)
- [Troubleshooting](#troubleshooting)

## Overview

mod_http3 enables HTTP/3 protocol support in Apache HTTP Server. The module:
- Creates a separate worker thread for handling HTTP/3 connections over UDP/QUIC
- Uses OpenSSL for QUIC/TLS 1.3 support
- Uses nghttp3 for HTTP/3 protocol handling
- Integrates with Apache's standard request processing pipeline

## Requirements

### Build Dependencies
- Apache HTTP Server 2.4+
- OpenSSL 3.x with QUIC support
- nghttp3 library
- APR (Apache Portable Runtime)

### Runtime Requirements
- Valid TLS certificate and private key
- UDP port availability (default: 4433)

## Configuration Directives

### H3CertificatePath

**Syntax:** `H3CertificatePath /path/to/certificate.pem`
**Context:** server config, virtual host
**Required:** Yes

Specifies the path to the TLS certificate file for HTTP/3 connections.

**Example:**
```apache
H3CertificatePath /etc/httpd/ssl/server.crt
```

**Notes:**
- The certificate must be in PEM format
- The file must be readable by the Apache user
- The certificate should be valid for the server's hostname

### H3CertificateKeyPath

**Syntax:** `H3CertificateKeyPath /path/to/private-key.pem`
**Context:** server config, virtual host
**Required:** Yes

Specifies the path to the TLS private key file for HTTP/3 connections.

**Example:**
```apache
H3CertificateKeyPath /etc/httpd/ssl/server.key
```

**Notes:**
- The private key must be in PEM format
- The file must be readable by the Apache user
- The key should not be password-protected (or configure Apache to handle passphrase)
- Ensure proper file permissions (typically 0600 or 0400)

## Basic Configuration

### Minimal Configuration

The simplest configuration requires loading the module and specifying certificate paths:

```apache
LoadModule http3_module modules/mod_http3.so

H3CertificatePath /etc/httpd/ssl/server.crt
H3CertificateKeyPath /etc/httpd/ssl/server.key
```

This configuration:
- Listens on the default port (4433) for HTTP/3 connections
- Uses the specified certificate and key for all HTTP/3 traffic

### Recommended Configuration

For production use, configure the port explicitly in a VirtualHost:

```apache
LoadModule http3_module modules/mod_http3.so

<VirtualHost *:4433>
    ServerName example.com

    H3CertificatePath /etc/httpd/ssl/example.com.crt
    H3CertificateKeyPath /etc/httpd/ssl/example.com.key

    DocumentRoot /var/www/html

    <Directory /var/www/html>
        Require all granted
    </Directory>
</VirtualHost>
```

## VirtualHost Configuration

### Port Detection

The module automatically detects the port from the VirtualHost configuration:

```apache
# HTTP/3 will listen on port 8443
<VirtualHost *:8443>
    ServerName secure.example.com

    H3CertificatePath /etc/httpd/ssl/secure.crt
    H3CertificateKeyPath /etc/httpd/ssl/secure.key
</VirtualHost>
```

If no port is specified in any VirtualHost address, the module defaults to **port 4433**.

### Multiple VirtualHosts

When using multiple VirtualHosts, the module uses the **first VirtualHost** that has both `H3CertificatePath` and `H3CertificateKeyPath` configured:

```apache
# This VirtualHost will be used for HTTP/3 (first with both directives)
<VirtualHost *:4433>
    ServerName primary.example.com
    H3CertificatePath /etc/httpd/ssl/primary.crt
    H3CertificateKeyPath /etc/httpd/ssl/primary.key
</VirtualHost>

# This VirtualHost will be ignored for HTTP/3
<VirtualHost *:4433>
    ServerName secondary.example.com
    H3CertificatePath /etc/httpd/ssl/secondary.crt
    H3CertificateKeyPath /etc/httpd/ssl/secondary.key
</VirtualHost>
```

**Note:** Currently, only the first configured VirtualHost with valid certificate paths is used for HTTP/3.

### Configuration Inheritance

Configuration merging follows Apache's standard behavior:
- Settings in VirtualHost contexts override global settings
- If a directive is not set in a VirtualHost, the global value is used

```apache
# Global fallback
H3CertificatePath /etc/httpd/ssl/default.crt
H3CertificateKeyPath /etc/httpd/ssl/default.key

<VirtualHost *:4433>
    ServerName example.com
    # Uses global certificate/key settings
</VirtualHost>

<VirtualHost *:4443>
    ServerName secure.example.com
    # Overrides global settings
    H3CertificatePath /etc/httpd/ssl/secure.crt
    H3CertificateKeyPath /etc/httpd/ssl/secure.key
</VirtualHost>
```

## Configuration Validation

### Startup Validation

The module validates configuration during Apache startup:

1. **Certificate Path Check:** Ensures `H3CertificatePath` is configured
   - **Error:** `mod_http3: H3CertificatePath directive is required but not configured`

2. **Key Path Check:** Ensures `H3CertificateKeyPath` is configured
   - **Error:** `mod_http3: H3CertificateKeyPath directive is required but not configured`

If either check fails, Apache will refuse to start and return an HTTP 500 error code.

### Testing Configuration

Test your configuration before restarting Apache:

```bash
# Test configuration syntax
httpd -t

# Test with verbose output
httpd -t -D DUMP_VHOSTS

# Check module loading
httpd -M | grep http3
```

### Verifying HTTP/3 Operation

After starting Apache, verify HTTP/3 is working:

```bash
# Check if Apache is listening on the UDP port
netstat -ulnp | grep httpd
# or
ss -ulnp | grep httpd

# Test with curl (if HTTP/3 support is available)
curl --http3 https://example.com:4433/

# Check Apache error log
tail -f /var/log/httpd/error_log
```

## Troubleshooting

### Common Issues

#### Apache Fails to Start

**Error:** `mod_http3: H3CertificatePath directive is required but not configured`

**Solution:** Ensure both `H3CertificatePath` and `H3CertificateKeyPath` are configured in at least one location (global or VirtualHost).

#### Certificate/Key File Errors

**Symptoms:** Apache starts but HTTP/3 connections fail

**Solutions:**
- Verify file paths are correct and absolute
- Check file permissions (Apache user must be able to read the files)
- Ensure certificate and key are in PEM format
- Verify certificate matches the private key

#### Port Already in Use

**Symptoms:** Apache starts but HTTP/3 doesn't listen

**Solutions:**
- Check if another process is using the UDP port: `netstat -ulnp | grep 4433`
- Use a different port in your VirtualHost configuration
- Stop conflicting services

#### Worker Thread Errors

**Symptoms:** Errors in logs mentioning thread creation

**Solutions:**
- Check system ulimits for the Apache user
- Verify MPM configuration allows thread creation
- Review system resource limits

### Debug Logging

Enable trace logging to troubleshoot configuration issues:

```apache
LogLevel http3:trace8
```

This will log detailed information about:
- Configuration loading and merging
- Certificate and key paths being used
- Port detection and binding
- Worker thread creation
- HTTP/3 connection handling

### Log Messages

Key log messages to look for:

```
# Successful configuration
h3_post_config: [PID] cert_path=/path/to/cert key_path=/path/to/key

# Worker thread started
h3_child_init
worker_thread_main

# Configuration errors
mod_http3: H3CertificatePath directive is required but not configured
mod_http3: H3CertificateKeyPath directive is required but not configured

# Thread creation failure
h3_child_init: Failed to create worker thread: [error code]
```

## Security Considerations

### File Permissions

Protect your private key:

```bash
# Set restrictive permissions
chmod 600 /etc/httpd/ssl/server.key
chown root:root /etc/httpd/ssl/server.key

# Or if Apache runs as a different user
chown apache:apache /etc/httpd/ssl/server.key
```

### Certificate Validation

Ensure your certificate:
- Is valid (not expired)
- Matches your server's hostname
- Includes the full certificate chain if using intermediate CAs
- Uses strong cryptographic algorithms (avoid SHA-1, MD5)

### TLS Configuration

While mod_http3 handles HTTP/3-specific TLS, consider these best practices:
- Use strong cipher suites
- Enable HSTS (HTTP Strict Transport Security)
- Regularly update certificates before expiration
- Use certificates from trusted CAs for production

## Examples

### Single Server Configuration

```apache
LoadModule http3_module modules/mod_http3.so

ServerName example.com

H3CertificatePath /etc/httpd/ssl/example.com.crt
H3CertificateKeyPath /etc/httpd/ssl/example.com.key

DocumentRoot /var/www/html
```

### Multiple Sites with Name-Based VirtualHosts

```apache
LoadModule http3_module modules/mod_http3.so

# Global defaults (optional)
H3CertificatePath /etc/httpd/ssl/default.crt
H3CertificateKeyPath /etc/httpd/ssl/default.key

# Primary site (HTTP/3 enabled)
<VirtualHost *:4433>
    ServerName www.example.com
    ServerAlias example.com

    H3CertificatePath /etc/httpd/ssl/example.com.crt
    H3CertificateKeyPath /etc/httpd/ssl/example.com.key

    DocumentRoot /var/www/example
</VirtualHost>

# Secondary site (uses global defaults)
<VirtualHost *:4433>
    ServerName blog.example.com
    DocumentRoot /var/www/blog
</VirtualHost>
```

### Custom Port Configuration

```apache
LoadModule http3_module modules/mod_http3.so

<VirtualHost *:8443>
    ServerName secure.example.com

    H3CertificatePath /etc/httpd/ssl/secure.crt
    H3CertificateKeyPath /etc/httpd/ssl/secure.key

    DocumentRoot /var/www/secure

    LogLevel http3:trace8
    ErrorLog /var/log/httpd/h3_error.log
    CustomLog /var/log/httpd/h3_access.log combined
</VirtualHost>
```

## Additional Resources

- Apache HTTP Server Documentation: https://httpd.apache.org/docs/
- HTTP/3 Specification: https://www.rfc-editor.org/rfc/rfc9114.html
- QUIC Protocol: https://www.rfc-editor.org/rfc/rfc9000.html
- OpenSSL QUIC Support: https://www.openssl.org/docs/

## Support

For issues and bug reports, consult:
- Apache error logs
- Module trace logs (with `LogLevel http3:trace8`)
- System logs for resource or permission issues
