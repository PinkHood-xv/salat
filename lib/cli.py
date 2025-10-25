"""
SALAT v2 - Command Line Interface
Argument parsing and validation for professional CLI tool
"""

import argparse
import ipaddress
import os
import sys
from datetime import datetime, timedelta


def create_parser():
    """Create and configure argument parser"""

    examples_text = """
EXAMPLES:
  Basic analysis:
    salat auth.json
    salat capture.pcap

  Filter by IP:
    salat -s 192.168.1.100 auth.json
    salat -d 10.0.0.5 --protocol tcp auth.json

  Time filtering:
    salat --start 2024-10-24 --end 2024-10-25 auth.json
    salat -L 24 auth.json

  Detection:
    salat -D brute-force auth.json
    salat -D all -t 3 auth.json

  Output formats:
    salat -F html -o report.html auth.json
    salat -D all -F json auth.json

  Educational mode:
    salat -c -s 192.168.1.100 auth.json

  Complete example:
    salat -s 192.168.1.100 -p 22 --protocol tcp \\
          -D all -F html -c -v auth.json
"""

    parser = argparse.ArgumentParser(
        description='SALAT v2 - SOC Analyst Log Analysis Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples_text
    )

    # Positional argument (optional for some flags)
    parser.add_argument('log_file', nargs='?',
                       help='Path to log file to analyze')

    # File/Format options
    format_group = parser.add_argument_group('File Options')
    format_group.add_argument('-f', '--format',
                            choices=['json', 'pcap', 'evtx', 'syslog'],
                            help='Log file format (auto-detected if not specified)')

    # Filter options
    filter_group = parser.add_argument_group('Filter Options')
    filter_group.add_argument('-s', '--src-ip',
                            help='Filter by source IP address or CIDR range')
    filter_group.add_argument('-d', '--dst-ip',
                            help='Filter by destination IP address or CIDR range')
    filter_group.add_argument('-S', '--start',
                            help='Start date/time (YYYY-MM-DD or "YYYY-MM-DD HH:MM:SS")')
    filter_group.add_argument('-E', '--end',
                            help='End date/time (YYYY-MM-DD or "YYYY-MM-DD HH:MM:SS")')
    filter_group.add_argument('-L', '--last-hours', type=int,
                            help='Analyze last N hours')
    filter_group.add_argument('-P', '--protocol',
                            choices=['tcp', 'udp', 'icmp', 'http', 'https', 'dns', 'ssh'],
                            help='Filter by protocol')
    filter_group.add_argument('-p', '--port', type=int,
                            help='Filter by port number')

    # Detection options
    detection_group = parser.add_argument_group('Detection Options')
    detection_group.add_argument('-D', '--detect',
                               help='Comma-separated detection types: brute-force,port-scan,all')
    detection_group.add_argument('-t', '--threshold', type=int, default=5,
                               help='Custom threshold for detections (default: 5)')
    detection_group.add_argument('-w', '--time-window', type=int, default=300,
                               help='Time window for detection in seconds (default: 300)')

    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output',
                            help='Output file path')
    output_group.add_argument('-F', '--output-format',
                            choices=['text', 'json', 'html', 'csv'],
                            default='text',
                            help='Output format (default: text)')
    output_group.add_argument('-T', '--timeline',
                            choices=['ascii', 'html', 'both', 'none'],
                            default='none',
                            help='Generate timeline visualization (default: none)')
    output_group.add_argument('-N', '--no-color', action='store_true',
                            help='Disable colored output')

    # Display options
    display_group = parser.add_argument_group('Display Options')
    display_group.add_argument('-v', '--verbose', action='store_true',
                             help='Verbose output (show all events)')
    display_group.add_argument('-q', '--quiet', action='store_true',
                             help='Quiet mode (only show detections)')
    display_group.add_argument('-c', '--show-commands', action='store_true',
                             help='Display educational manual commands')
    display_group.add_argument('-l', '--limit', type=int,
                             help='Limit number of results shown')
    display_group.add_argument('-m', '--summary-only', action='store_true',
                             help='Show only summary statistics')

    # Info options
    info_group = parser.add_argument_group('Information')
    info_group.add_argument('--version', action='version', version='SALAT v2.0.0')
    info_group.add_argument('--list-detectors', action='store_true',
                          help='List available detection modules')
    info_group.add_argument('--examples', action='store_true',
                          help='Show example usage commands')

    return parser


def parse_arguments(argv=None):
    """Parse command line arguments"""
    parser = create_parser()
    args = parser.parse_args(argv)
    return args


def validate_arguments(args):
    """Validate argument combinations and values"""
    errors = []

    # Check file exists (if log_file is provided)
    if args.log_file and not os.path.exists(args.log_file):
        errors.append(f"Log file not found: {args.log_file}")

    # Require log_file for most operations
    if not args.log_file and not (args.examples or args.list_detectors):
        errors.append("Log file is required for analysis operations")

    # Validate IP addresses
    if args.src_ip:
        try:
            ipaddress.ip_network(args.src_ip, strict=False)
        except ValueError:
            errors.append(f"Invalid source IP/CIDR: {args.src_ip}")

    if args.dst_ip:
        try:
            ipaddress.ip_network(args.dst_ip, strict=False)
        except ValueError:
            errors.append(f"Invalid destination IP/CIDR: {args.dst_ip}")

    # Validate date formats
    if args.start:
        try:
            parse_datetime(args.start)
        except ValueError:
            errors.append(f"Invalid start date format: {args.start}")

    if args.end:
        try:
            parse_datetime(args.end)
        except ValueError:
            errors.append(f"Invalid end date format: {args.end}")

    # Check incompatible options
    if args.verbose and args.quiet:
        errors.append("Cannot use both --verbose and --quiet")

    if args.start and args.last_hours:
        errors.append("Cannot use both --start and --last-hours")

    if args.end and args.last_hours:
        errors.append("Cannot use both --end and --last-hours")

    # Validate port range
    if args.port and not (1 <= args.port <= 65535):
        errors.append(f"Port must be between 1-65535: {args.port}")

    # Validate thresholds
    if args.threshold < 1:
        errors.append(f"Threshold must be positive: {args.threshold}")

    if args.time_window < 1:
        errors.append(f"Time window must be positive: {args.time_window}")

    # Validate limit
    if args.limit and args.limit < 1:
        errors.append(f"Limit must be positive: {args.limit}")

    if errors:
        print("Error: " + "\n       ".join(errors), file=sys.stderr)
        sys.exit(1)


def parse_datetime(date_str):
    """Parse datetime string in various formats"""
    formats = [
        '%Y-%m-%d',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S'
    ]

    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue

    raise ValueError(f"Invalid date format: {date_str}")


def get_examples():
    """Get example commands"""
    return """
SALAT v2 - Example Commands:

Basic Analysis:
  salat auth.json
  salat capture.pcap

Filtering:
  salat -s 192.168.1.100 auth.json
  salat -d 10.0.0.5 -P tcp auth.json
  salat -p 22 -S 2024-10-24 auth.json
  salat -L 24 auth.json

Detection:
  salat -D brute-force auth.json
  salat -D port-scan,brute-force auth.json
  salat -D all -t 3 auth.json

Output Formats:
  salat -F html auth.json
  salat -o report.html -F html auth.json
  salat -D all -F json auth.json

Educational Mode:
  salat -c -s 192.168.1.100 auth.json
  salat -D all -c -v auth.json

Advanced:
  salat -s 192.168.1.100 -p 22 -P tcp -D all -c -v auth.json
  salat -L 24 -D all -F html -T html auth.json
  salat -D brute-force -t 3 -w 180 -F json -o output.json auth.json
"""


def get_detectors_list():
    """Get list of available detectors"""
    return """
Available Detection Modules:

brute-force     - Detect brute force authentication attacks
                  (Multiple failed login attempts from same source)

port-scan       - Detect port scanning activity
                  (Connections to multiple ports from same source)

all            - Run all available detectors

Usage:
  --detect brute-force
  --detect port-scan
  --detect brute-force,port-scan
  --detect all

Customization:
  --threshold N     - Set detection threshold (default: 5)
  --time-window N   - Set time window in seconds (default: 300)
"""