# Testing Andy VulnScanner

## Overview
Andy VulnScanner is a Python tkinter GUI vulnerability scanner for Kali Linux. It has port scanning and website scanning capabilities.

## How to Launch

```bash
cd /home/ubuntu/repos/vulnscanner
/usr/bin/python3 -m vulnscanner.main
```

**Important:** Use system Python (`/usr/bin/python3`) - pyenv Python may not have tkinter installed.

## GUI Structure

The app has 5 tabs:
1. **Open Ports** - Port scan results (Port, State, Service, Version/Banner)
2. **Vulnerabilities** - CVE/vulnerability matches from scan results
3. **Web Scanner** - Website vulnerability scanning (URL input, findings treeview, detail panel)
4. **Console** - Real-time scan log output
5. **Export** - Export results to CSV, HTML, or clipboard

Top config bar has: Target IP, Scan Type dropdown, Ports field, Timeout, Threads, Start/Stop buttons.

## Testing Port Scanner

1. Default target is `127.0.0.1` with "Common Ports" scan type
2. Click "Start Scan" - should find port 22/SSH/OpenSSH on localhost
3. Results appear in Open Ports treeview and Console tab
4. Check Vulnerabilities tab for any CVE matches

## Testing Web Scanner

1. Click "Web Scanner" tab
2. Enter a URL (default: `https://example.com`)
3. Toggle "Directory Scan" checkbox (on = slower but checks 30+ common paths)
4. Click "Scan Website"
5. Verify:
   - Findings treeview populates with severity-colored rows (Critical=red, High=orange, Medium=yellow, Low=blue, Info=green)
   - Summary bar shows URL, IP, finding count, severity breakdown, scan time
   - Clicking a finding row shows details in bottom panel (Title, Severity, Category, Description, Recommendation)
   - Console tab shows detailed scan log (security headers, SSL/TLS info, technologies, directories)

## Key Test Targets

- `https://example.com` - Good for testing security header findings (typically 7 missing headers)
- `127.0.0.1` - Good for port scanning (SSH on port 22)

## Known Behaviors

- Port scan and web scan share a single `is_scanning` flag - they cannot run concurrently
- Directory scan sends 30+ HTTP requests - significantly slower than header-only scan
- Web scan export is not yet integrated into the Export tab (only port scan results export)
- SSL verification is intentionally disabled for initial HTTP request to handle sites with bad certs

## Lint

```bash
ruff check vulnscanner/
```

## No External Dependencies

The project uses only Python stdlib (including tkinter). No pip install needed.
