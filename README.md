# Andy VulnScanner

A Python-based vulnerability scanner with a dark-themed GUI, built for Kali Linux.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Features

- **Port Scanning** - Fast multi-threaded TCP port scanning with configurable threads and timeout
- **Service Detection** - Automatic service identification and banner grabbing
- **Vulnerability Detection** - Checks open services against a built-in vulnerability database with CVE references
- **Dark GUI** - Modern dark-themed interface inspired by Kali Linux aesthetics
- **Risk Scoring** - Calculates overall risk score (0-100) based on detected vulnerabilities
- **Export Reports** - Export results as CSV, HTML, or copy as plain text
- **Real-time Console** - Live scan output with color-coded log messages

## Screenshots

The GUI features:
- **Open Ports tab** - Displays all discovered open ports with service info and banners
- **Vulnerabilities tab** - Lists detected vulnerabilities with severity, CVE, and detailed descriptions
- **Console tab** - Real-time colored log output during scanning
- **Export tab** - One-click export to CSV or styled HTML reports

## Installation

### Prerequisites

- Python 3.8 or higher
- Tkinter (usually included with Python on Kali Linux)

### Install from source

```bash
git clone https://github.com/andyzaylaa/andy-vulnscanner.git
cd andy-vulnscanner
pip install -e .
```

### Run directly

```bash
python -m vulnscanner.main
```

Or after installation:

```bash
andy-vulnscanner
```

## Usage

1. **Enter Target** - Type an IP address or hostname in the Target field
2. **Select Scan Type**:
   - *Common Ports* - Scans the most commonly used ports (fast)
   - *Full Scan* - Scans all 65,535 ports (thorough but slower)
   - *Custom Ports* - Specify your own ports (e.g., `80,443,8080` or `1-1024`)
3. **Configure Options** - Adjust timeout and thread count as needed
4. **Start Scan** - Click "Start Scan" or press Enter
5. **Review Results** - Check the Open Ports and Vulnerabilities tabs
6. **Export** - Save results as CSV or HTML from the Export tab

## Scan Types

| Type | Ports | Speed | Use Case |
|------|-------|-------|----------|
| Common | ~27 key ports | Fast | Quick reconnaissance |
| Full | 1-65535 | Slow | Thorough assessment |
| Custom | User-defined | Varies | Targeted scanning |

## Vulnerability Database

The built-in vulnerability database checks for:

- Outdated service versions (SSH, FTP, HTTP servers, databases)
- Known backdoors (e.g., vsFTPd 2.3.4)
- Insecure services (Telnet, exposed databases)
- Common misconfigurations (unauthenticated Redis/MongoDB)
- Critical exposures (RDP BlueKeep, SMB EternalBlue indicators)

## Project Structure

```
andy-vulnscanner/
├── vulnscanner/
│   ├── __init__.py          # Package init
│   ├── main.py              # Entry point
│   ├── gui/
│   │   ├── __init__.py
│   │   └── app.py           # Main GUI application
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── port_scanner.py  # Port scanning engine
│   │   └── vuln_checker.py  # Vulnerability checker
│   └── reports/
│       ├── __init__.py
│       └── exporter.py      # CSV/HTML/Text export
├── setup.py
├── requirements.txt
├── LICENSE
└── README.md
```

## Disclaimer

**This tool is intended for authorized security testing and educational purposes only.**
Always obtain proper authorization before scanning any network or system.
Unauthorized scanning may be illegal in your jurisdiction.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**Andy** - Vulnerability Scanner for Kali Linux
