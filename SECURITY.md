# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅        |

## Reporting a Vulnerability

Please open a private security advisory on GitHub, or contact the maintainer directly. Do not open public issues for security vulnerabilities.

## Scope

- This service only reads public CT log data; it stores nothing sensitive.
- The SQLite cache (`data/`) contains only public subdomain names and is gitignored.
- No authentication/credentials are required or stored.
