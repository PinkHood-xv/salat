# SALAT - Command Reference

Complete reference for all command-line options with their short and long forms.

## Quick Reference Table

| Short | Long | Description | Example |
|-------|------|-------------|---------|
| | **File Options** |
| `-f` | `--format` | Specify log format | `-f json` |
| | **Filter Options** |
| `-s` | `--src-ip` | Source IP/CIDR | `-s 192.168.1.100` |
| `-d` | `--dst-ip` | Destination IP/CIDR | `-d 10.0.0.0/24` |
| `-S` | `--start` | Start date/time | `-S 2024-10-24` |
| `-E` | `--end` | End date/time | `-E 2024-10-25` |
| `-L` | `--last-hours` | Last N hours | `-L 24` |
| `-P` | `--protocol` | Protocol filter | `-P tcp` |
| `-p` | `--port` | Port number | `-p 22` |
| | **Detection Options** |
| `-D` | `--detect` | Detection types | `-D brute-force` |
| `-t` | `--threshold` | Detection threshold | `-t 5` |
| `-w` | `--time-window` | Time window (seconds) | `-w 300` |
| | **Output Options** |
| `-o` | `--output` | Output file path | `-o report.html` |
| `-F` | `--output-format` | Output format | `-F html` |
| `-T` | `--timeline` | Timeline visualization | `-T html` |
| `-N` | `--no-color` | Disable colors | `-N` |
| | **Display Options** |
| `-v` | `--verbose` | Verbose output | `-v` |
| `-q` | `--quiet` | Quiet mode | `-q` |
| `-c` | `--show-commands` | Show manual commands | `-c` |
| `-l` | `--limit` | Limit results | `-l 100` |
| `-m` | `--summary-only` | Summary only | `-m` |

## Detailed Options

### File Options

#### `-f, --format {json,pcap,evtx,syslog}`
Explicitly specify the log file format. If not provided, SALAT will auto-detect the format.

```bash
salat -f json auth.log
salat --format pcap network.cap
```

### Filter Options

#### `-s, --src-ip IP_OR_CIDR`
Filter events by source IP address or CIDR range.

```bash
salat -s 192.168.1.100 auth.json
salat --src-ip 10.0.0.0/24 logs.json
```

#### `-d, --dst-ip IP_OR_CIDR`
Filter events by destination IP address or CIDR range.

```bash
salat -d 8.8.8.8 traffic.pcap
salat --dst-ip 192.168.0.0/16 logs.json
```

#### `-S, --start DATETIME`
Start date/time for filtering. Formats accepted:
- `YYYY-MM-DD`
- `YYYY-MM-DD HH:MM:SS`
- `YYYY-MM-DDTHH:MM:SS`

```bash
salat -S 2024-10-24 auth.json
salat --start "2024-10-24 14:30:00" auth.json
```

#### `-E, --end DATETIME`
End date/time for filtering. Same formats as `--start`.

```bash
salat -E 2024-10-25 auth.json
salat --end "2024-10-24 18:00:00" auth.json
```

#### `-L, --last-hours N`
Analyze only the last N hours of logs.

```bash
salat -L 24 auth.json          # Last 24 hours
salat --last-hours 2 auth.json  # Last 2 hours
```

#### `-P, --protocol {tcp,udp,icmp,http,https,dns,ssh}`
Filter by network protocol.

```bash
salat -P tcp logs.json
salat --protocol ssh auth.json
```

#### `-p, --port PORT`
Filter by port number (1-65535).

```bash
salat -p 22 network.pcap
salat --port 443 logs.json
```

### Detection Options

#### `-D, --detect TYPES`
Enable threat detection. Comma-separated list or 'all'.

**Detection types:**
- `brute-force` - Brute force authentication attacks
- `port-scan` - Port scanning activity
- `all` - All available detectors

```bash
salat -D brute-force auth.json
salat -D port-scan,brute-force logs.json
salat --detect all logs.json
```

#### `-t, --threshold N`
Set the detection threshold (default: 5).

For brute-force: Number of failed attempts
For port-scan: Number of unique ports

```bash
salat -D brute-force -t 3 auth.json
salat --detect port-scan --threshold 10 network.pcap
```

#### `-w, --time-window SECONDS`
Time window for detection in seconds (default: 300).

```bash
salat -D brute-force -w 180 auth.json      # 3 minutes
salat --detect all --time-window 600 logs.json  # 10 minutes
```

### Output Options

#### `-o, --output FILE`
Write output to specified file instead of stdout.

```bash
salat -o report.txt auth.json
salat --output analysis.html -F html logs.json
```

#### `-F, --output-format {text,json,html,csv}`
Specify output format (default: text).

```bash
salat -F html auth.json
salat -F json -o output.json logs.json
salat --output-format csv logs.json
```

#### `-T, --timeline {ascii,html,both,none}`
Generate timeline visualization (default: none).

```bash
salat -D all -T html auth.json
salat --detect all --timeline both logs.json
```

#### `-N, --no-color`
Disable colored terminal output.

```bash
salat -N auth.json
salat --no-color logs.json
```

### Display Options

#### `-v, --verbose`
Show verbose output including all events.

```bash
salat -v auth.json
salat --verbose -D all logs.json
```

#### `-q, --quiet`
Quiet mode - only show detection alerts.

```bash
salat -q -D all auth.json
salat --quiet --detect brute-force logs.json
```

#### `-c, --show-commands`
Display educational manual commands that achieve similar results.

```bash
salat -c -s 192.168.1.100 auth.json
salat --show-commands -D all logs.json
```

#### `-l, --limit N`
Limit the number of results displayed.

```bash
salat -l 100 auth.json
salat --limit 50 -v logs.json
```

#### `-m, --summary-only`
Show only summary statistics without event details.

```bash
salat -m auth.json
salat --summary-only -D all logs.json
```

### Information Options

#### `--version`
Show version information.

```bash
salat --version
```

#### `--list-detectors`
List all available detection modules with descriptions.

```bash
salat --list-detectors
```

#### `--examples`
Show comprehensive example commands.

```bash
salat --examples
```

## Common Usage Patterns

### Quick Analysis
```bash
# Basic log analysis
salat auth.json

# With detections
salat -D all auth.json
```

### Investigation
```bash
# Investigate specific IP
salat -s 192.168.1.100 -D all -c auth.json

# Check SSH activity
salat -P tcp -p 22 -L 24 -v logs.json

# Brute force detection with custom threshold
salat -D brute-force -t 3 -w 180 auth.json
```

### Reporting
```bash
# HTML report
salat -D all -F html -o report.html auth.json

# JSON for automation
salat -D all -F json -o output.json logs.json

# Timeline with detections
salat -D all -T html -F html -o analysis.html logs.json
```

### Learning Mode
```bash
# Show manual commands
salat -c -s 192.168.1.100 auth.json

# Verbose with manual commands
salat -v -c -D all logs.json
```

### Complex Analysis
```bash
# Multi-filter with detection
salat -s 192.168.1.0/24 -P tcp -p 22 -L 24 -D brute-force -t 3 auth.json

# Full analysis with report
salat -s 10.0.0.0/8 -D all -F html -T html -c -o full_report.html logs.json

# Custom detection parameters
salat -D port-scan -t 20 -w 60 -F json -o scan_results.json network.pcap
```

## Option Incompatibilities

Some options cannot be used together:

- `-v` and `-q` (verbose and quiet are mutually exclusive)
- `-S` and `-L` (start time and last-hours are mutually exclusive)
- `-E` and `-L` (end time and last-hours are mutually exclusive)

## Tips

1. **Short options are stackable** (when they don't take arguments):
   ```bash
   salat -vq auth.json  # This will error (incompatible)
   salat -vc auth.json  # Verbose + show-commands (works!)
   ```

2. **Combine short and long** for readability:
   ```bash
   salat -s 192.168.1.100 --detect all -c auth.json
   ```

3. **Use quotes** for values with spaces:
   ```bash
   salat -S "2024-10-24 14:30:00" auth.json
   ```

4. **Pipeline with other tools**:
   ```bash
   salat -D all -F json logs.json | jq '.detections'
   ```

## Getting Help

```bash
salat --help          # Show all options
salat --examples      # Show example commands
salat --list-detectors # Show available detectors
```

---

**SALAT** - Professional SOC Analysis Made Simple
