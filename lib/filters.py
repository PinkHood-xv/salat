"""
SALAT v2 - Event Filtering Engine
Filter events based on command-line criteria
"""

import ipaddress
from datetime import datetime, timedelta
from lib.cli import parse_datetime


def apply_filters(events, args):
    """
    Apply all filters from command-line args

    Args:
        events: List of normalized events
        args: Parsed command-line arguments

    Returns:
        List of filtered events
    """
    filtered = events

    # IP filters
    if args.src_ip:
        filtered = filter_by_src_ip(filtered, args.src_ip)

    if args.dst_ip:
        filtered = filter_by_dst_ip(filtered, args.dst_ip)

    # Time filters
    if args.start and args.end:
        start_dt = parse_datetime(args.start)
        end_dt = parse_datetime(args.end)
        filtered = filter_by_time_range(filtered, start_dt, end_dt)

    elif args.last_hours:
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=args.last_hours)
        filtered = filter_by_time_range(filtered, start_time, end_time)

    # Protocol filter
    if args.protocol:
        filtered = filter_by_protocol(filtered, args.protocol)

    # Port filter
    if args.port:
        filtered = filter_by_port(filtered, args.port)

    return filtered


def filter_by_src_ip(events, ip_or_cidr):
    """Filter by source IP or CIDR range"""
    try:
        network = ipaddress.ip_network(ip_or_cidr, strict=False)
    except ValueError:
        raise ValueError(f"Invalid IP/CIDR format: {ip_or_cidr}")

    filtered = []
    for event in events:
        src_ip = event.get('src_ip')
        if src_ip:
            try:
                ip = ipaddress.ip_address(src_ip)
                if ip in network:
                    filtered.append(event)
            except ValueError:
                # Skip events with invalid IP addresses
                continue

    return filtered


def filter_by_dst_ip(events, ip_or_cidr):
    """Filter by destination IP or CIDR range"""
    try:
        network = ipaddress.ip_network(ip_or_cidr, strict=False)
    except ValueError:
        raise ValueError(f"Invalid IP/CIDR format: {ip_or_cidr}")

    filtered = []
    for event in events:
        dst_ip = event.get('dst_ip')
        if dst_ip:
            try:
                ip = ipaddress.ip_address(dst_ip)
                if ip in network:
                    filtered.append(event)
            except ValueError:
                # Skip events with invalid IP addresses
                continue

    return filtered


def filter_by_time_range(events, start_time, end_time):
    """Filter by time range"""
    filtered = []

    for event in events:
        timestamp_str = event.get('timestamp')
        if not timestamp_str:
            continue

        try:
            # Try to parse the timestamp
            event_time = parse_event_timestamp(timestamp_str)
            if start_time <= event_time <= end_time:
                filtered.append(event)
        except ValueError:
            # Skip events with unparseable timestamps
            continue

    return filtered


def filter_by_protocol(events, protocol):
    """Filter by protocol"""
    protocol_upper = protocol.upper()

    filtered = []
    for event in events:
        event_protocol = event.get('protocol')
        if event_protocol and event_protocol.upper() == protocol_upper:
            filtered.append(event)

    return filtered


def filter_by_port(events, port):
    """Filter by port (source or destination)"""
    filtered = []

    for event in events:
        src_port = event.get('src_port')
        dst_port = event.get('dst_port')

        # Convert to int for comparison
        try:
            if src_port and int(src_port) == port:
                filtered.append(event)
                continue
            if dst_port and int(dst_port) == port:
                filtered.append(event)
                continue
        except (ValueError, TypeError):
            # Skip events with invalid port numbers
            continue

    return filtered


def parse_event_timestamp(timestamp_str):
    """Parse timestamp from event (various formats)"""
    formats = [
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%b %d %H:%M:%S',
        '%Y-%m-%d',
        '%Y/%m/%d %H:%M:%S',
        '%d/%b/%Y:%H:%M:%S'
    ]

    # Remove timezone info if present
    clean_timestamp = timestamp_str.split('+')[0].split('Z')[0].split('.')[0]

    for fmt in formats:
        try:
            return datetime.strptime(clean_timestamp, fmt)
        except ValueError:
            continue

    # If all formats fail, try to extract just the date part
    try:
        date_part = clean_timestamp.split()[0]
        return datetime.strptime(date_part, '%Y-%m-%d')
    except (ValueError, IndexError):
        pass

    raise ValueError(f"Unable to parse timestamp: {timestamp_str}")


def get_filter_summary(args):
    """Get summary of applied filters for display"""
    filters = []

    if args.src_ip:
        filters.append(f"Source IP: {args.src_ip}")

    if args.dst_ip:
        filters.append(f"Destination IP: {args.dst_ip}")

    if args.protocol:
        filters.append(f"Protocol: {args.protocol.upper()}")

    if args.port:
        filters.append(f"Port: {args.port}")

    if args.start and args.end:
        filters.append(f"Time: {args.start} to {args.end}")

    elif args.last_hours:
        filters.append(f"Last {args.last_hours} hours")

    return filters