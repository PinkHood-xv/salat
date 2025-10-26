# SALAT - SOC Analyst Log Analysis Toolkit

Professional command-line security log analysis and threat detection tool.

## Quick Start

```bash
# Basic analysis
./salat sample_logs/auth_sample.json

# Filter by IP and detect attacks
./salat -s 192.168.1.100 -D brute-force sample_logs/auth_sample.json

# Generate HTML report
./salat -D all -F html -o report.html sample_logs/auth_sample.json

# Show manual commands for learning
./salat -c -s 192.168.1.100 sample_logs/auth_sample.json
```

## Overview

SALAT is designed as a command-line tool following Unix conventions. It provides:

- **Multi-format log parsing** (JSON, PCAP, EVTX, Syslog)
- **Advanced filtering** by IP, time, protocol, ports
- **Automated threat detection** (brute force, port scans)
- **Multiple output formats** (text, JSON, HTML, CSV)
- **Educational commands** showing manual analysis techniques
- **Timeline visualization** for security events

## Key Features

### Powerful Filtering (Like jq + tcpdump)
SALAT reads and filters log files with syntax similar to popular tools:
- **Display all events** - View complete log contents with `-v`
- **IP filtering** - Source/destination IP or CIDR ranges (`-s`, `-d`)
- **Port filtering** - Any port, source or destination (`-p`)
- **Protocol filtering** - TCP, UDP, HTTP, DNS, SSH, etc. (`-P`)
- **Time filtering** - Date ranges or last N hours (`-S`, `-E`, `-L`)
- **Combined filters** - Stack multiple filters like tcpdump
- **Multiple outputs** - Text, JSON, HTML, CSV formats (`-F`)

**Example:** `./salat -s 192.168.1.100 -P tcp -p 22 -L 24 -v auth.json`
*(Like: `jq '.[] | select(.src_ip=="192.168.1.100" and .port==22)' auth.json`)*

See [FILTERING_GUIDE.md](FILTERING_GUIDE.md) for complete filtering documentation.

### Supported Log Formats
- **JSON** - Application logs, API logs, structured data
- **PCAP** - Network traffic captures (requires tshark)
- **EVTX** - Windows Event Logs (requires python-evtx)
- **Syslog** - Unix/Linux system logs

### Detection Capabilities
- **Brute Force Attacks** - Multiple failed authentication attempts
- **Port Scanning** - Reconnaissance activity detection
- **Customizable thresholds** and time windows

### Output Formats
- **Text** - Human-readable terminal output
- **JSON** - Machine-readable for automation
- **HTML** - Interactive reports with visualization
- **CSV** - Spreadsheet-compatible format

## Installation

### Requirements
- Python 3.7+
- Optional: `tshark` for PCAP analysis
- Optional: `python-evtx` for Windows Event Log support

### Setup
```bash
# Clone or extract SALAT v2
cd salat_v2

# Make executable
chmod +x salat

# Test installation
./salat --help
```

## 🔧 Usage

### Basic Syntax
```bash
salat [OPTIONS] <log_file>
```

### Quick Reference - Short Options

Most options have convenient short versions for faster typing:

| Short | Long | Description |
|-------|------|-------------|
| `-s` | `--src-ip` | Source IP filter |
| `-d` | `--dst-ip` | Destination IP filter |
| `-p` | `--port` | Port filter |
| `-P` | `--protocol` | Protocol filter |
| `-S` | `--start` | Start date/time |
| `-E` | `--end` | End date/time |
| `-L` | `--last-hours` | Last N hours |
| `-D` | `--detect` | Enable detection |
| `-t` | `--threshold` | Detection threshold |
| `-w` | `--time-window` | Time window |
| `-F` | `--output-format` | Output format |
| `-o` | `--output` | Output file |
| `-T` | `--timeline` | Timeline mode |
| `-c` | `--show-commands` | Show manual commands |
| `-v` | `--verbose` | Verbose mode |
| `-q` | `--quiet` | Quiet mode |
| `-l` | `--limit` | Limit results |

**Quick Examples:**
```bash
# Short version (fast typing)
salat -s 192.168.1.100 -D brute-force -t 3 -c auth.json

# Long version (more readable)
salat --src-ip 192.168.1.100 --detect brute-force --threshold 3 --show-commands auth.json

# Mixed (common style)
salat -s 192.168.1.100 --detect all -c auth.json
```

See [COMMAND_REFERENCE.md](COMMAND_REFERENCE.md) for complete command documentation.

** New to filtering?** Check out the [FILTERING_GUIDE.md](FILTERING_GUIDE.md) for comprehensive examples showing how SALAT filtering works like `jq` and `tcpdump`.

### Filtering Options

```bash
# IP Filtering
./salat -s 192.168.1.100 logs.json          # Source IP
./salat -d 10.0.0.0/24 logs.json            # Destination CIDR

# Time Filtering
./salat -S 2024-10-24 logs.json             # Start date
./salat -L 24 logs.json                     # Last N hours

# Protocol/Port Filtering
./salat -P tcp -p 22 logs.json              # TCP port 22
./salat -P http logs.json                   # HTTP traffic
```

### Detection Options

```bash
# Specific detections
./salat -D brute-force logs.json
./salat -D port-scan logs.json
./salat -D brute-force,port-scan logs.json

# All detections
./salat -D all logs.json

# Custom thresholds
./salat -D brute-force -t 3 -w 180 logs.json
```

### Output Options

```bash
# Different formats
./salat -F json logs.json
./salat -F html -o report.html logs.json
./salat -F csv logs.json

# Timeline generation
./salat -D all -T html logs.json

# Verbose output
./salat -v -D all logs.json

# Quiet mode (alerts only)
./salat -q -D all logs.json
```

### Educational Mode

```bash
# Show equivalent manual commands
./salat -c -s 192.168.1.100 logs.json

# Example output:
# [jq command]
# jq '.[] | select(.src_ip == "192.168.1.100")' logs.json
#
# [Alternative: grep + jq]
# grep "192.168.1.100" logs.json | jq .
```

## Examples

### Basic Log Analysis
```bash
# Analyze JSON authentication logs
./salat sample_logs/auth_sample.json

# Quick PCAP analysis
./salat network_capture.pcap
```

### Security Investigation
```bash
# Look for brute force from specific IP
./salat -s 192.168.1.100 -D brute-force auth.json

# Investigate port scanning activity
./salat -D port-scan -t 5 network.pcap

# Full security analysis with timeline
./salat -D all -T html -o security_report.html logs.json
```

### Filtered Analysis
```bash
# SSH activity in last 24 hours
./salat -P tcp -p 22 -L 24 syslog.log

# HTTP traffic to specific subnet
./salat -d 10.0.0.0/24 -P http access.log

# Failed authentications in time range
./salat -S "2024-10-24 14:00:00" -E "2024-10-24 16:00:00" \
        -D brute-force auth.json
```

### Report Generation
```bash
# Generate comprehensive HTML report
./salat -D all -F html -T html -c -o complete_analysis.html logs.json

# CSV export for spreadsheet analysis
./salat -v -F csv -o events.csv logs.json

# JSON output for automation
./salat -D all -F json logs.json | jq .
```

## Educational Features

SALAT includes educational features to help SOC analysts learn manual analysis techniques:

### Manual Command Display
Use `-c` or `--show-commands` to see equivalent manual commands:

```bash
./salat -c -s 192.168.1.100 logs.json
```

Shows:
- **jq commands** for JSON analysis
- **tshark/tcpdump commands** for PCAP analysis
- **grep/awk commands** for syslog analysis
- **Wireshark display filters** for GUI analysis

### Detection Logic
Each detector shows the manual verification commands:
- Brute force: jq commands to group and count failed attempts
- Port scan: Commands to identify unique ports per source IP

## Detection Details

### Brute Force Detection
- **Logic**: Multiple failed authentication attempts from same source IP
- **Default threshold**: 5 attempts in 5 minutes
- **Indicators**: Failed login events, HTTP 401/403, authentication failures

### Port Scan Detection
- **Logic**: Connections to multiple unique ports from same source IP
- **Default threshold**: 10 unique ports in 1 minute
- **Types detected**: Service discovery, comprehensive scans, targeted scans

### Custom Detection
Both detectors support custom thresholds and time windows:
```bash
# Custom brute force: 3 attempts in 3 minutes
./salat -D brute-force -t 3 -w 180 logs.json

# Custom port scan: 20 ports in 30 seconds
./salat -D port-scan -t 20 -w 30 logs.json
```


## Development

### Adding New Detectors
1. Create detector class inheriting from `BaseDetector`
2. Implement `detect()` method
3. Add to detection orchestration in `lib/detectors.py`

### Adding New Parsers
1. Create parser in `parsers/` directory
2. Implement `parse_*()` function returning normalized events
3. Add format detection in `lib/parser.py`

### Adding New Output Formats
1. Create formatter in `formatters/` directory
2. Implement `format_*()` function
3. Add to format dispatcher in `lib/formatters.py`

## Roadmap

Future enhancements planned:
- Additional detection modules (SQL injection, XSS, data exfiltration)
- Real-time log monitoring capabilities
- Integration with SIEM platforms
- Advanced statistical analysis
- Machine learning-based anomaly detection

## Support

For issues, questions, or contributions:
- Review documentation in this README
- Check sample commands with `./salat --examples`
- Use `./salat --help` for complete options
- Test with provided sample logs

## License

SALAT is designed for educational and professional SOC analysis purposes.

---

**SALAT** - Professional SOC Analysis Made Simple
