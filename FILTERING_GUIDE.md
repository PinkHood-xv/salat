# SALAT v2 - Complete Filtering Guide

This guide demonstrates SALAT's filtering capabilities, which work similarly to popular tools like `jq` (for JSON) and `tcpdump`/`tshark` (for network traffic).

## Overview

SALAT can:
1. **Read and display all log entries** from various formats
2. **Filter events** using multiple criteria (IP, port, protocol, time)
3. **Combine filters** for complex queries
4. **Output in multiple formats** (text, JSON, HTML, CSV)
5. **Show equivalent manual commands** for learning

---

## Basic Operations

### Display All Events

Show all events in a log file (like `jq '.'` or `cat`):

```bash
# Show all events with verbose details
./salat -v auth.json

# Show all events with limit
./salat -v -l 10 auth.json

# Show all events as JSON (like jq)
./salat -F json auth.json

# Show all events as CSV
./salat -F csv auth.json
```

### Count Events

```bash
# Show summary with event count
./salat -m auth.json

# JSON output shows statistics
./salat -F json auth.json | jq '.statistics.total_events'
```

---

## IP-Based Filtering

### Single IP Address

**Like jq:** `jq '.[] | select(.src_ip == "192.168.1.100")'`
**SALAT:**
```bash
# Filter by source IP
./salat -s 192.168.1.100 auth.json

# Filter by destination IP
./salat -d 10.0.0.5 auth.json

# Verbose output with IP filter
./salat -s 192.168.1.100 -v auth.json
```

### CIDR Range

**Like jq:** `jq '.[] | select(.src_ip | startswith("192.168"))'`
**SALAT:**
```bash
# Filter by source subnet
./salat -s 192.168.0.0/16 auth.json

# Filter by destination subnet
./salat -d 10.0.0.0/24 auth.json

# Show only events from private network
./salat -s 172.16.0.0/12 auth.json
```

### Both Source and Destination

**Like tcpdump:** `tcpdump 'src host 192.168.1.100 and dst host 10.0.0.5'`
**SALAT:**
```bash
# Both source and destination filters
./salat -s 192.168.1.100 -d 10.0.0.5 auth.json
```

---

## Port-Based Filtering

### Single Port

**Like tcpdump:** `tcpdump 'port 22'`
**SALAT:**
```bash
# Filter by port (source OR destination)
./salat -p 22 auth.json

# SSH traffic
./salat -p 22 network.pcap

# HTTP traffic
./salat -p 80 access.log

# Show verbose details
./salat -p 443 -v traffic.json
```

---

## Protocol Filtering

### Specific Protocol

**Like tcpdump:** `tcpdump 'tcp'`
**SALAT:**
```bash
# Filter by TCP
./salat -P tcp network.json

# Filter by UDP
./salat -P udp network.json

# Application protocols
./salat -P http access.log
./salat -P ssh auth.log
./salat -P dns dns.log
```

---

## Time-Based Filtering

### Time Range

**Like jq:** Complex timestamp comparison
**SALAT:**
```bash
# Between specific dates
./salat -S 2024-10-24 -E 2024-10-25 auth.json

# With time (24-hour format)
./salat -S "2024-10-24 14:00:00" -E "2024-10-24 16:00:00" auth.json

# ISO format also supported
./salat -S 2024-10-24T14:00:00 auth.json
```

### Last N Hours

**Like:** `jq '.[] | select(.timestamp > (now - 86400))'`
**SALAT:**
```bash
# Last 24 hours
./salat -L 24 auth.json

# Last hour
./salat -L 1 auth.json

# Last 2 hours
./salat -L 2 auth.json
```

---

## Combined Filtering

### Multiple Filters (AND Logic)

**Like tcpdump:** `tcpdump 'tcp and port 22 and src host 192.168.1.100'`
**SALAT:**
```bash
# Protocol + Port
./salat -P tcp -p 22 auth.json

# IP + Port
./salat -s 192.168.1.100 -p 22 auth.json

# IP + Protocol + Port
./salat -s 192.168.1.100 -P tcp -p 22 auth.json

# All filters combined
./salat -s 192.168.1.0/24 -d 10.0.0.0/8 -P tcp -p 443 -L 24 network.json
```

### Real-World Examples

```bash
# Find all SSH attempts from specific IP in last hour
./salat -s 192.168.1.100 -P tcp -p 22 -L 1 -v auth.json

# Analyze HTTP traffic to specific subnet today
./salat -P http -d 10.0.0.0/24 -S 2024-10-24 access.log

# Check all traffic to/from specific host
./salat -s 192.168.1.50 -v network.pcap

# Find DNS queries in time window
./salat -P dns -p 53 -S "2024-10-24 10:00:00" -E "2024-10-24 11:00:00" dns.log
```

---

## Output Formatting

### Text Output (Default)

```bash
# Human-readable text
./salat -s 192.168.1.100 auth.json

# Verbose details
./salat -s 192.168.1.100 -v auth.json

# Quiet mode (detections only)
./salat -s 192.168.1.100 -D all -q auth.json

# Summary only
./salat -s 192.168.1.100 -m auth.json
```

### JSON Output

**Like jq output:**
```bash
# All events as JSON
./salat -F json auth.json

# Filtered events as JSON
./salat -s 192.168.1.100 -F json auth.json

# Pipe to jq for further processing
./salat -s 192.168.1.100 -F json auth.json | jq '.events[] | {timestamp, src_ip, message}'

# Get statistics only
./salat -F json auth.json | jq '.statistics'
```

### CSV Output

**For spreadsheet analysis:**
```bash
# Export to CSV
./salat -F csv -o events.csv auth.json

# Filtered to CSV
./salat -s 192.168.1.0/24 -F csv -o subnet_events.csv auth.json
```

### HTML Output

**For reporting:**
```bash
# Generate HTML report
./salat -F html -o report.html auth.json

# With detections and timeline
./salat -D all -F html -T html -o full_report.html auth.json
```

---

## Result Limiting

```bash
# Show first 10 events
./salat -v -l 10 auth.json

# Show first 50 events from filter
./salat -s 192.168.1.100 -v -l 50 auth.json

# Summary of first 100
./salat -l 100 network.json
```

---

## Educational Mode - Learn the Commands

Show equivalent manual commands (jq, grep, tcpdump):

```bash
# Show how to do it manually
./salat -c -s 192.168.1.100 auth.json

# With filtering
./salat -c -P tcp -p 22 auth.json

# With detection
./salat -c -D brute-force auth.json
```

**Example output:**
```
MANUAL ANALYSIS COMMANDS:
============================================================
[Tool: jq - JSON Query Language]
jq '.[] | select(.src_ip == "192.168.1.100")' auth.json
  └─ .src_ip == "192.168.1.100" filters by source IP

[Alternative: grep + jq for quick searches]
grep -E '192.168.1.100' auth.json | jq .
```

---

## Comparison with Traditional Tools

### vs. jq (JSON filtering)

| Operation | jq | SALAT |
|-----------|-----|-------|
| Show all | `jq '.' file.json` | `./salat -v file.json` |
| Filter IP | `jq '.[] \| select(.src_ip == "X")' file.json` | `./salat -s X file.json` |
| Count | `jq '. \| length' file.json` | `./salat -m file.json` |
| JSON output | `jq '.' file.json` | `./salat -F json file.json` |
| Multiple filters | Complex jq query | `./salat -s X -p Y -P tcp file.json` |

### vs. tcpdump/tshark (PCAP filtering)

| Operation | tcpdump | SALAT |
|-----------|---------|-------|
| Read file | `tcpdump -r file.pcap` | `./salat file.pcap` |
| Filter IP | `tcpdump -r file.pcap src host X` | `./salat -s X file.pcap` |
| Filter port | `tcpdump -r file.pcap port 22` | `./salat -p 22 file.pcap` |
| Protocol | `tcpdump -r file.pcap tcp` | `./salat -P tcp file.pcap` |
| Combined | `tcpdump -r file.pcap 'tcp and port 22 and src host X'` | `./salat -s X -P tcp -p 22 file.pcap` |
| JSON output | `tshark -r file.pcap -T json` | `./salat -F json file.pcap` |

### vs. grep (syslog filtering)

| Operation | grep/awk | SALAT |
|-----------|----------|-------|
| Read file | `cat syslog` | `./salat syslog` |
| Filter IP | `grep '192.168.1.100' syslog` | `./salat -s 192.168.1.100 syslog` |
| Time range | Complex awk script | `./salat -S "2024-10-24" -E "2024-10-25" syslog` |
| Count | `grep 'pattern' syslog \| wc -l` | `./salat -m syslog` |

---

## Advanced Filtering Patterns

### Network Traffic Analysis

```bash
# All SSH connections
./salat -P tcp -p 22 -v network.pcap

# Internal network communication
./salat -s 192.168.0.0/16 -d 192.168.0.0/16 network.pcap

# External connections only
./salat -s 192.168.1.0/24 -v network.pcap | grep -v "192.168"

# Suspicious high ports
./salat -P tcp -v network.pcap | grep -E ":[4-6][0-9]{4}"
```

### Authentication Analysis

```bash
# Failed logins from specific IP
./salat -s 192.168.1.100 -v auth.json

# All authentication in last hour
./salat -L 1 -v auth.json

# SSH attempts to specific server
./salat -d 10.0.0.5 -p 22 auth.json
```

### Time-Based Investigation

```bash
# Events during incident window
./salat -S "2024-10-24 14:00:00" -E "2024-10-24 14:30:00" -v logs.json

# Recent activity (last 2 hours)
./salat -L 2 -v logs.json

# Specific day
./salat -S 2024-10-24 -E 2024-10-25 logs.json
```

### Protocol-Specific Analysis

```bash
# HTTP traffic only
./salat -P http -v access.log

# DNS queries
./salat -P dns -v network.pcap

# All TCP connections
./salat -P tcp -v network.json
```

---

## Piping and Integration

### Pipe to Other Tools

```bash
# SALAT to jq
./salat -s 192.168.1.100 -F json auth.json | jq '.events[].message'

# SALAT to grep
./salat -v auth.json | grep "Failed"

# SALAT to wc
./salat -s 192.168.1.0/24 -v auth.json | wc -l

# Export and analyze in spreadsheet
./salat -F csv network.pcap > traffic.csv
```

### Automation Examples

```bash
# Daily report
./salat -L 24 -D all -F html -o daily_$(date +%Y%m%d).html auth.json

# Check specific IP daily
./salat -s 192.168.1.100 -L 24 -F json auth.json > ip_activity.json

# Export recent events
./salat -L 1 -F csv -o last_hour.csv network.json
```

---

## Performance Tips

1. **Use specific filters** - Narrow down early with IP/port filters
2. **Limit output** - Use `-l` flag for large datasets
3. **Summary mode** - Use `-m` for quick statistics
4. **JSON for piping** - Use `-F json` when piping to other tools
5. **Quiet mode** - Use `-q` when only interested in detections

---

## Quick Reference

```bash
# Display
./salat -v file.json              # Show all events
./salat -v -l 10 file.json        # Limit to 10
./salat -m file.json              # Summary only

# Filter by IP
./salat -s IP file.json           # Source IP
./salat -d IP file.json           # Dest IP
./salat -s CIDR file.json         # CIDR range

# Filter by port/protocol
./salat -p PORT file.json         # Port
./salat -P PROTO file.json        # Protocol

# Filter by time
./salat -L HOURS file.json        # Last N hours
./salat -S DATE file.json         # Start date
./salat -E DATE file.json         # End date

# Output formats
./salat -F json file.json         # JSON
./salat -F csv file.json          # CSV
./salat -F html file.json         # HTML

# Combine filters
./salat -s IP -P tcp -p 22 -L 24 -v file.json

# Learn mode
./salat -c -s IP file.json        # Show manual commands
```

---

## Summary

SALAT provides **powerful filtering** similar to `jq` and `tcpdump` but:
- ✅ Works across **multiple log formats** (JSON, PCAP, syslog, EVTX)
- ✅ **Simple syntax** - easier than complex jq queries or tcpdump filters
- ✅ **Combined operations** - filter + analyze + detect in one command
- ✅ **Multiple outputs** - text, JSON, HTML, CSV
- ✅ **Educational** - shows equivalent manual commands with `-c`

**The result:** Professional log analysis with the power of traditional tools but easier to use!
