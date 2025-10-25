"""
SALAT v2 - Log File Parser
Load and parse log files using appropriate format-specific parsers
"""

import os
from pathlib import Path


def detect_format(filename):
    """Auto-detect file format from extension"""
    suffix = Path(filename).suffix.lower()

    format_map = {
        '.json': 'json',
        '.pcap': 'pcap',
        '.pcapng': 'pcap',
        '.cap': 'pcap',
        '.evtx': 'evtx',
        '.log': 'syslog',
        '.txt': 'syslog'
    }

    return format_map.get(suffix, 'unknown')


def load_log_file(filename, format=None):
    """
    Load log file using appropriate parser

    Args:
        filename: Path to log file
        format: Force specific format (optional)

    Returns:
        List of normalized event dictionaries
    """
    if not os.path.exists(filename):
        raise FileNotFoundError(f"File not found: {filename}")

    # Auto-detect format if not specified
    if format is None:
        format = detect_format(filename)

    # Dispatch to appropriate parser
    if format == 'json':
        from parsers.json_parser import parse_json
        return parse_json(filename)

    elif format == 'pcap':
        from parsers.pcap_parser import parse_pcap
        return parse_pcap(filename)

    elif format == 'evtx':
        from parsers.evtx_parser import parse_evtx
        return parse_evtx(filename)

    elif format == 'syslog':
        from parsers.syslog_parser import parse_syslog
        return parse_syslog(filename)

    else:
        raise ValueError(f"Unsupported file format: {format}")


def normalize_event(event, source_format):
    """
    Normalize event to standard field names

    Standard fields:
    - timestamp: ISO format datetime string
    - src_ip: Source IP address
    - dst_ip: Destination IP address
    - src_port: Source port
    - dst_port: Destination port
    - protocol: Protocol (TCP, UDP, etc.)
    - event_type: Type of event
    - message: Event description
    - severity: Event severity level
    - raw: Original event data
    """
    normalized = {
        'timestamp': None,
        'src_ip': None,
        'dst_ip': None,
        'src_port': None,
        'dst_port': None,
        'protocol': None,
        'event_type': None,
        'message': None,
        'severity': 'info',
        'raw': event
    }

    if source_format == 'json':
        # Common JSON field mappings
        field_mappings = {
            'timestamp': ['timestamp', 'time', '@timestamp', 'datetime'],
            'src_ip': ['src_ip', 'source_ip', 'client_ip', 'source'],
            'dst_ip': ['dst_ip', 'dest_ip', 'destination_ip', 'destination', 'target_ip'],
            'src_port': ['src_port', 'source_port', 'client_port'],
            'dst_port': ['dst_port', 'dest_port', 'destination_port', 'target_port'],
            'protocol': ['protocol', 'proto'],
            'event_type': ['event_type', 'type', 'action', 'event'],
            'message': ['message', 'msg', 'description', 'details'],
            'severity': ['severity', 'level', 'priority']
        }

        for standard_field, possible_fields in field_mappings.items():
            for field in possible_fields:
                if field in event and event[field] is not None:
                    normalized[standard_field] = event[field]
                    break

    elif source_format == 'pcap':
        # PCAP data is already normalized by tshark
        normalized.update(event)

    return normalized