# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅       |

## Reporting a Vulnerability

This is a Purple Team adversarial validation tool. If you discover a security vulnerability, please do NOT open a public issue.

Contact the maintainer directly at jefferson.antunes@gmail.com with details about the issue.

We commit to acknowledging receipt within 48 hours and providing a fix timeline within 7 days.

## Known Limitations

- **TOCTOU in /proc analysis**: The tool reads /proc/self/maps to detect RWX regions. Between the time the file is read and analysis is performed, memory mappings could theoretically change. This is single-threaded and the window is negligible, but it is a documented inherent limitation.
- **Shellcode execution**: The tool executes benign exit(0) shellcode in child processes as part of Purple Team adversarial validation. This is an intentional feature, not a vulnerability.
- **Process masquerading**: The tool renames child processes via prctl() for adversarial simulation. This is an intentional feature.
