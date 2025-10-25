"""
SALAT v2 - Syslog Parser
Parse syslog format files
"""

import re
from datetime import datetime
from lib.parser import normalize_event


def parse_syslog(filename):
    """
    Parse syslog file

    Args:
        filename: Path to syslog file

    Returns:
        List of normalized events
    """
    events = []

    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    event = parse_syslog_line(line)
                    if event:
                        normalized = normalize_event(event, 'syslog')
                        events.append(normalized)
                except Exception:
                    # Skip malformed lines
                    continue

    except Exception as e:
        raise ValueError(f"Failed to parse syslog file: {e}")

    return events


def parse_syslog_line(line):
    """Parse a single syslog line"""
    # RFC3164 syslog format: <priority>timestamp hostname tag: message
    # RFC5424 syslog format: <priority>version timestamp hostname app-name procid msgid structured-data msg

    # Try RFC3164 format first
    rfc3164_pattern = r'^(<\d+>)?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)$'
    match = re.match(rfc3164_pattern, line)

    if match:
        priority, timestamp_str, hostname, tag, message = match.groups()

        event = {
            'timestamp': parse_syslog_timestamp(timestamp_str),
            'hostname': hostname,
            'tag': tag,
            'message': message,
            'event_type': 'syslog'
        }

        # Extract priority if present
        if priority:
            try:
                pri = int(priority.strip('<>'))
                facility = pri >> 3
                severity = pri & 7
                event['facility'] = facility
                event['severity'] = map_syslog_severity(severity)
            except ValueError:
                pass

        # Try to extract IP addresses from message
        extract_ips_from_message(event, message)

        # Try to extract more specific event type
        event['event_type'] = determine_syslog_event_type(tag, message)

        return event

    # Try simpler format (just timestamp + message)
    simple_pattern = r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(.*)$'
    match = re.match(simple_pattern, line)

    if match:
        timestamp_str, message = match.groups()

        event = {
            'timestamp': timestamp_str,
            'message': message,
            'event_type': 'log_entry'
        }

        extract_ips_from_message(event, message)
        return event

    # If no pattern matches, treat as generic log entry
    return {
        'timestamp': None,
        'message': line,
        'event_type': 'log_entry'
    }


def parse_syslog_timestamp(timestamp_str):
    """Parse syslog timestamp"""
    try:
        # Add current year if not present
        current_year = datetime.now().year

        # Common syslog timestamp format: "Oct 24 14:23:15"
        dt = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        return dt.isoformat()
    except ValueError:
        return timestamp_str


def map_syslog_severity(severity_code):
    """Map syslog severity code to text"""
    severity_map = {
        0: 'emergency',
        1: 'alert',
        2: 'critical',
        3: 'error',
        4: 'warning',
        5: 'notice',
        6: 'info',
        7: 'debug'
    }
    return severity_map.get(severity_code, 'unknown')


def determine_syslog_event_type(tag, message):
    """Determine specific event type from syslog tag and message"""
    tag_lower = tag.lower() if tag else ''
    message_lower = message.lower()

    # SSH events
    if 'ssh' in tag_lower or 'sshd' in tag_lower:
        if any(keyword in message_lower for keyword in ['failed', 'invalid', 'authentication failure']):
            return 'ssh_failed_login'
        elif any(keyword in message_lower for keyword in ['accepted', 'session opened']):
            return 'ssh_successful_login'
        else:
            return 'ssh_event'

    # Authentication events
    if any(keyword in tag_lower for keyword in ['auth', 'login', 'su', 'sudo']):
        if any(keyword in message_lower for keyword in ['failed', 'failure', 'invalid']):
            return 'authentication_failure'
        elif any(keyword in message_lower for keyword in ['success', 'accepted', 'opened']):
            return 'authentication_success'
        else:
            return 'authentication'

    # Firewall events
    if any(keyword in tag_lower for keyword in ['firewall', 'iptables', 'pf']):
        if any(keyword in message_lower for keyword in ['drop', 'deny', 'block']):
            return 'firewall_drop'
        elif any(keyword in message_lower for keyword in ['accept', 'allow']):
            return 'firewall_allow'
        else:
            return 'firewall_event'

    # Web server events
    if any(keyword in tag_lower for keyword in ['apache', 'nginx', 'httpd']):
        return 'web_server'

    # System events
    if any(keyword in tag_lower for keyword in ['kernel', 'systemd', 'init']):
        return 'system_event'

    return 'syslog'


def extract_ips_from_message(event, message):
    """Extract IP addresses from syslog message"""
    # IP address pattern
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, message)

    if ips:
        # Look for context clues to determine source vs destination
        message_lower = message.lower()

        for ip in ips:
            if any(keyword in message_lower for keyword in ['from', 'source', 'src']):
                # IP likely to be source
                if not event.get('src_ip'):
                    event['src_ip'] = ip
            elif any(keyword in message_lower for keyword in ['to', 'destination', 'dst', 'target']):
                # IP likely to be destination
                if not event.get('dst_ip'):
                    event['dst_ip'] = ip
            else:
                # Default to source if no context
                if not event.get('src_ip'):
                    event['src_ip'] = ip


def extract_ports_from_message(event, message):
    """Extract port numbers from syslog message"""
    # Port pattern (after "port", ":", or standalone numbers in likely contexts)
    port_patterns = [
        r'port\s+(\d+)',
        r':(\d+)\b',
        r'\bport=(\d+)',
        r'dpt=(\d+)',
        r'spt=(\d+)'
    ]

    for pattern in port_patterns:
        matches = re.findall(pattern, message, re.IGNORECASE)
        for match in matches:
            try:
                port = int(match)
                if 1 <= port <= 65535:
                    if 'spt' in pattern or 'source' in message.lower():
                        event['src_port'] = port
                    elif 'dpt' in pattern or 'dest' in message.lower():
                        event['dst_port'] = port
                    elif not event.get('dst_port'):
                        event['dst_port'] = port
            except ValueError:
                continue