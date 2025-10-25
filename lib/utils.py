"""
SALAT v2 - Utility Functions
Educational commands and helper functions
"""

import os
from pathlib import Path


def show_educational_commands(args):
    """
    Display equivalent manual commands for educational purposes

    Args:
        args: Parsed command-line arguments
    """
    # Check if any filters are applied or detection is used
    has_filters = any([args.src_ip, args.dst_ip, args.protocol, args.port,
                      args.start, args.end, args.last_hours])
    has_detection = bool(args.detect)

    file_format = args.format or detect_file_format(args.log_file)
    is_pcap = file_format == 'pcap' or args.log_file.endswith(('.pcap', '.pcapng'))

    # Always show for PCAP files (network traffic), or when filters/detection/show-commands
    if is_pcap or has_filters or has_detection or args.show_commands:
        print("MANUAL ANALYSIS COMMANDS:")
        print("=" * 60)
        if is_pcap:
            print("💡 Network traffic analysis - Wireshark filters always shown")
        else:
            print("💡 These commands achieve the same filtering manually")
        print()

        if file_format == 'json' or args.log_file.endswith('.json'):
            show_json_commands(args)

        elif is_pcap:
            # Always show Wireshark filters for PCAP files
            show_pcap_commands(args)

        elif file_format == 'syslog' or args.log_file.endswith(('.log', '.txt')):
            show_syslog_commands(args)

        print("💡 Use these commands to verify SALAT's results manually")
        print("=" * 60)


def show_json_commands(args):
    """Show equivalent jq and grep commands for JSON files"""
    has_filters = any([args.src_ip, args.dst_ip, args.protocol, args.port,
                      args.start, args.end, args.last_hours])
    has_detection = bool(args.detect)

    if has_filters or has_detection or args.show_commands:
        print("[Tool: jq - JSON Query Language]")

        # Build jq command
        jq_cmd = build_jq_command(args)
        # Extract the jq filter part
        filter_part = jq_cmd.split("'")[1] if "'" in jq_cmd else jq_cmd
        print(f"jq '{filter_part}' {args.log_file}")

        # Show what each part does
        if args.src_ip:
            print(f"  └─ .src_ip == \"{args.src_ip}\" filters by source IP")
        if args.dst_ip:
            print(f"  └─ .dst_ip == \"{args.dst_ip}\" filters by destination IP")
        if args.protocol:
            print(f"  └─ .protocol == \"{args.protocol.upper()}\" filters by protocol")
        if args.port:
            print(f"  └─ (.src_port == {args.port} or .dst_port == {args.port}) filters by port")

        # Alternative grep command for simple IP searches
        if args.src_ip or args.dst_ip:
            print(f"\n[Alternative: grep + jq for quick searches]")
            grep_cmd = build_grep_json_command(args)
            print(f"{grep_cmd}")
            print("  └─ grep finds lines, jq formats the output")

        # Count and statistics commands
        print(f"\n[Count matching events]")
        count_cmd = build_jq_command(args).replace(args.log_file, f"{args.log_file} | jq length")
        print(f"{count_cmd}")

    # Show detection commands
    if args.detect:
        show_detection_commands(args, 'json')


def show_pcap_commands(args):
    """Show equivalent tshark and Wireshark commands for PCAP files"""
    has_filters = any([args.src_ip, args.dst_ip, args.protocol, args.port,
                      args.start, args.end, args.last_hours])
    has_detection = bool(args.detect)

    # Always show Wireshark filter for network traffic
    print("🔍 [WIRESHARK DISPLAY FILTER - COPY & PASTE]")
    print("=" * 50)
    wireshark_filter = build_wireshark_filter(args)

    if wireshark_filter and wireshark_filter != 'No filters applied':
        print(f"📋 {wireshark_filter}")
        print("   └─ Paste this into Wireshark's display filter bar")

        # Explain each filter component
        filter_explanations = []
        if args.src_ip:
            filter_explanations.append(f"ip.src == {args.src_ip} (source IP)")
        if args.dst_ip:
            filter_explanations.append(f"ip.dst == {args.dst_ip} (destination IP)")
        if args.protocol:
            filter_explanations.append(f"{args.protocol.lower()} (protocol)")
        if args.port:
            filter_explanations.append(f"port {args.port} (any port)")

        if filter_explanations:
            print(f"   └─ Filters: {' + '.join(filter_explanations)}")
    else:
        # Suggest common useful filters even when no specific filters applied
        print("📋 Suggested filters for network analysis:")
        print("   • tcp and (tcp.flags.syn == 1)           - TCP connection attempts")
        print("   • http                                    - HTTP traffic only")
        print("   • dns                                     - DNS queries/responses")
        print("   • tcp.analysis.flags                     - TCP issues (retrans, etc)")
        print("   • ip.addr == X.X.X.X                     - Traffic to/from specific IP")

    if has_filters or has_detection or args.show_commands:
        print(f"\n[Tool: tshark - Command Line Analysis]")

        # Build tshark command
        tshark_cmd = build_tshark_command(args)
        print(f"{tshark_cmd}")

        # Alternative tcpdump command
        print(f"\n[Alternative: tcpdump - Packet Capture]")
        tcpdump_cmd = build_tcpdump_command(args)
        print(f"{tcpdump_cmd}")
        print("  └─ tcpdump uses Berkeley Packet Filter (BPF) syntax")

        # Network analysis suggestions
        print(f"\n[Network Analysis Suggestions]")
        print(f"# Follow TCP streams:")
        print(f"tshark -r {args.log_file} -q -z follow,tcp,ascii,0")
        print(f"# Protocol hierarchy:")
        print(f"tshark -r {args.log_file} -q -z prot,colinfo")
        print(f"# Conversations by endpoint:")
        print(f"tshark -r {args.log_file} -q -z endpoints,ip")
        print(f"# Get packet details:")
        print(f"tshark -r {args.log_file} -V | less")


def show_syslog_commands(args):
    """Show equivalent grep, awk, and sed commands for syslog files"""
    has_filters = any([args.src_ip, args.dst_ip, args.protocol, args.port,
                      args.start, args.end, args.last_hours])
    has_detection = bool(args.detect)

    if has_filters or has_detection or args.show_commands:
        print("[Tool: grep - Text Pattern Matching]")

        # Build grep command
        grep_cmd = build_grep_syslog_command(args)
        print(f"{grep_cmd}")

        # Explain the patterns
        if args.src_ip:
            print(f"  └─ {args.src_ip} matches source IP addresses")
        if args.dst_ip:
            print(f"  └─ {args.dst_ip} matches destination IP addresses")
        if args.protocol:
            print(f"  └─ {args.protocol.upper()} matches protocol names")

        # Show awk alternatives for more complex parsing
        if args.src_ip or args.dst_ip:
            print(f"\n[Alternative: awk - Pattern Processing]")
            awk_cmd = build_awk_command(args)
            print(f"{awk_cmd}")
            print("  └─ awk provides more powerful field-based processing")

        # Time-based filtering with awk
        if args.start or args.end or args.last_hours:
            print(f"\n[Time-based filtering with awk]")
            print(f"awk '$0 ~ /Oct 24/ {{print}}' {args.log_file}")
            print("  └─ Filter by date patterns in syslog timestamps")

        # Count occurrences
        print(f"\n[Count matching lines]")
        simple_pattern = args.src_ip or args.dst_ip or args.protocol or "pattern"
        print(f"grep -c '{simple_pattern}' {args.log_file}")
        print("  └─ Count total matches without showing content")


def build_jq_command(args):
    """Build equivalent jq command for JSON filtering"""
    filters = []

    # Build jq select conditions
    if args.src_ip:
        filters.append(f'.src_ip == "{args.src_ip}"')

    if args.dst_ip:
        filters.append(f'.dst_ip == "{args.dst_ip}"')

    if args.protocol:
        filters.append(f'.protocol == "{args.protocol.upper()}"')

    if args.port:
        filters.append(f'(.src_port == {args.port} or .dst_port == {args.port})')

    # Date filters
    if args.start:
        filters.append(f'.timestamp >= "{args.start}"')

    if args.end:
        filters.append(f'.timestamp <= "{args.end}"')

    # Build complete command
    if filters:
        condition = ' and '.join(filters)
        return f'jq \'.[] | select({condition})\' {args.log_file}'
    else:
        return f'jq \'.[]\' {args.log_file}'


def build_grep_json_command(args):
    """Build grep command for JSON files"""
    grep_terms = []

    if args.src_ip:
        grep_terms.append(args.src_ip)

    if args.dst_ip:
        grep_terms.append(args.dst_ip)

    if args.protocol:
        grep_terms.append(args.protocol)

    if grep_terms:
        pattern = '|'.join(grep_terms)
        return f"grep -E '{pattern}' {args.log_file} | jq ."
    else:
        return f"cat {args.log_file} | jq ."


def build_tshark_command(args):
    """Build equivalent tshark command for PCAP filtering"""
    filters = []

    # Build display filter
    if args.src_ip:
        filters.append(f'ip.src == {args.src_ip}')

    if args.dst_ip:
        filters.append(f'ip.dst == {args.dst_ip}')

    if args.protocol:
        proto_map = {
            'tcp': 'tcp',
            'udp': 'udp',
            'icmp': 'icmp',
            'http': 'http',
            'https': 'tls',
            'dns': 'dns',
            'ssh': 'ssh'
        }
        proto_filter = proto_map.get(args.protocol.lower(), args.protocol.lower())
        filters.append(proto_filter)

    if args.port:
        filters.append(f'(tcp.port == {args.port} || udp.port == {args.port})')

    # Build command
    base_cmd = f'tshark -r {args.log_file}'

    if filters:
        filter_str = ' && '.join(filters)
        return f'{base_cmd} -Y "{filter_str}" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e _ws.col.Protocol'
    else:
        return f'{base_cmd} -T fields -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e _ws.col.Protocol'


def build_tcpdump_command(args):
    """Build equivalent tcpdump command"""
    filters = []

    if args.src_ip:
        filters.append(f'src host {args.src_ip}')

    if args.dst_ip:
        filters.append(f'dst host {args.dst_ip}')

    if args.protocol:
        proto = args.protocol.lower()
        if proto in ['tcp', 'udp', 'icmp']:
            filters.append(proto)
        elif proto == 'http':
            filters.append('tcp port 80')
        elif proto == 'https':
            filters.append('tcp port 443')
        elif proto == 'dns':
            filters.append('udp port 53')
        elif proto == 'ssh':
            filters.append('tcp port 22')

    if args.port:
        filters.append(f'port {args.port}')

    filter_str = ' and '.join(filters) if filters else ''
    return f'tcpdump -r {args.log_file} {filter_str} -n'


def build_wireshark_filter(args):
    """Build Wireshark display filter"""
    filters = []

    if args.src_ip:
        filters.append(f'ip.src == {args.src_ip}')

    if args.dst_ip:
        filters.append(f'ip.dst == {args.dst_ip}')

    if args.protocol:
        proto_map = {
            'tcp': 'tcp',
            'udp': 'udp',
            'icmp': 'icmp',
            'http': 'http',
            'https': 'tls',
            'dns': 'dns',
            'ssh': 'ssh'
        }
        proto_filter = proto_map.get(args.protocol.lower(), args.protocol.lower())
        filters.append(proto_filter)

    if args.port:
        filters.append(f'(tcp.port == {args.port} || udp.port == {args.port})')

    return ' && '.join(filters) if filters else 'No filters applied'


def build_grep_syslog_command(args):
    """Build grep command for syslog files"""
    grep_options = ['-n']  # Show line numbers

    patterns = []
    if args.src_ip:
        patterns.append(args.src_ip)

    if args.dst_ip:
        patterns.append(args.dst_ip)

    if args.protocol:
        patterns.append(args.protocol.upper())

    if patterns:
        pattern = '|'.join(patterns)
        return f"grep -E {''.join(grep_options)} '{pattern}' {args.log_file}"
    else:
        return f"cat {args.log_file}"


def build_awk_command(args):
    """Build awk command for syslog analysis"""
    conditions = []

    if args.src_ip:
        conditions.append(f'/{args.src_ip}/')

    if args.dst_ip:
        conditions.append(f'/{args.dst_ip}/')

    if conditions:
        condition_str = ' && '.join(conditions)
        return f"awk '{condition_str} {{print}}' {args.log_file}"
    else:
        return f"awk '{{print}}' {args.log_file}"


def show_detection_commands(args, file_format):
    """Show manual commands for detection verification"""
    detect_types = args.detect.split(',')

    if 'brute-force' in detect_types or 'all' in detect_types:
        print(f"\n[Manual Brute Force Detection - Step by Step]")
        print(f"Detection Logic: {args.threshold}+ failed auth attempts from same IP within {args.time_window}s")

        if file_format == 'json':
            print(f"\n1. Find all failed authentication events:")
            print(f'jq \'[.[] | select(.event_type | test("fail|denied|invalid"; "i"))]\' {args.log_file}')

            print(f"\n2. Group by source IP and count attempts:")
            print(f'jq \'[.[] | select(.event_type | test("fail|denied|invalid"; "i"))] | group_by(.src_ip)\' {args.log_file}')

            print(f"\n3. Find IPs with {args.threshold}+ attempts:")
            bf_cmd = f'jq \'[.[] | select(.event_type | test("fail|denied|invalid"; "i"))] | group_by(.src_ip) | map({{ip: .[0].src_ip, count: length, first: .[0].timestamp, last: .[-1].timestamp}}) | .[] | select(.count >= {args.threshold})\' {args.log_file}'
            print(f"{bf_cmd}")
            print("  └─ This shows the same results as SALAT's brute force detector")

    if 'port-scan' in detect_types or 'all' in detect_types:
        print(f"\n[Manual Port Scan Detection - Step by Step]")
        port_threshold = 10 if args.threshold == 5 else args.threshold
        print(f"Detection Logic: {port_threshold}+ unique ports from same IP within 60s")

        if file_format == 'json':
            print(f"\n1. Find all connection events with ports:")
            print(f'jq \'[.[] | select(.dst_port)]\' {args.log_file}')

            print(f"\n2. Group by source IP:")
            print(f'jq \'[.[] | select(.dst_port)] | group_by(.src_ip)\' {args.log_file}')

            print(f"\n3. Count unique ports per IP:")
            ps_cmd = f'jq \'[.[] | select(.dst_port)] | group_by(.src_ip) | map({{ip: .[0].src_ip, unique_ports: [.[].dst_port] | unique | length, ports: [.[].dst_port] | unique, total_attempts: length}}) | .[] | select(.unique_ports >= {port_threshold})\' {args.log_file}'
            print(f"{ps_cmd}")
            print("  └─ This shows the same results as SALAT's port scan detector")


def detect_file_format(filename):
    """Detect file format from extension"""
    suffix = Path(filename).suffix.lower()

    format_map = {
        '.json': 'json',
        '.pcap': 'pcap',
        '.pcapng': 'pcap',
        '.evtx': 'evtx',
        '.log': 'syslog',
        '.txt': 'syslog'
    }

    return format_map.get(suffix, 'unknown')


def format_bytes(bytes_count):
    """Format byte count in human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} TB"


def get_file_info(filename):
    """Get basic file information"""
    try:
        stat = os.stat(filename)
        return {
            'size': format_bytes(stat.st_size),
            'size_bytes': stat.st_size,
            'modified': stat.st_mtime
        }
    except OSError:
        return None


def validate_ip_address(ip_string):
    """Validate IP address format"""
    import ipaddress
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


def validate_cidr(cidr_string):
    """Validate CIDR format"""
    import ipaddress
    try:
        ipaddress.ip_network(cidr_string, strict=False)
        return True
    except ValueError:
        return False