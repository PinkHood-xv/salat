"""
SALAT v2 - JSON Output Formatter
Format analysis results as JSON
"""

import json
from datetime import datetime
from lib.filters import get_filter_summary
from lib.detectors import get_findings_summary


def format_json(events, findings, args):
    """
    Format output as JSON

    Args:
        events: List of filtered events
        findings: List of detection findings
        args: Parsed command-line arguments

    Returns:
        JSON formatted string
    """
    # Build the output structure
    output = {
        'metadata': {
            'tool': 'SALAT v2',
            'version': '2.0.0',
            'analysis_timestamp': datetime.now().isoformat(),
            'log_file': args.log_file,
            'format': args.format or 'auto-detected'
        },
        'configuration': {
            'filters': build_filters_config(args),
            'detection': build_detection_config(args)
        },
        'summary': {
            'total_events_analyzed': len(events),
            'events_after_filtering': len(events),
            'detections_found': len(findings),
            'time_range': get_time_range(events)
        },
        'findings': [],
        'events': []
    }

    # Add findings summary
    if findings:
        findings_summary = get_findings_summary(findings)
        output['summary']['findings_by_severity'] = findings_summary['by_severity']
        output['summary']['findings_by_detector'] = findings_summary['by_detector']

        # Add individual findings
        for finding in findings:
            output['findings'].append(format_finding_json(finding))

    # Add events (if requested)
    if not args.summary_only:
        events_to_include = events
        if args.limit:
            events_to_include = events[:args.limit]

        for event in events_to_include:
            output['events'].append(format_event_json(event))

    # Add statistics
    output['statistics'] = calculate_statistics(events)

    return json.dumps(output, indent=2, default=str)


def build_filters_config(args):
    """Build filters configuration for JSON output"""
    filters = {}

    if args.src_ip:
        filters['source_ip'] = args.src_ip
    if args.dst_ip:
        filters['destination_ip'] = args.dst_ip
    if args.protocol:
        filters['protocol'] = args.protocol
    if args.port:
        filters['port'] = args.port
    if args.start:
        filters['start_time'] = args.start
    if args.end:
        filters['end_time'] = args.end
    if args.last_hours:
        filters['last_hours'] = args.last_hours

    return filters


def build_detection_config(args):
    """Build detection configuration for JSON output"""
    config = {}

    if args.detect:
        config['enabled'] = True
        config['types'] = args.detect.split(',')
        config['threshold'] = args.threshold
        config['time_window'] = args.time_window
    else:
        config['enabled'] = False

    return config


def format_finding_json(finding):
    """Format a finding for JSON output"""
    json_finding = {
        'id': f"finding_{hash(str(finding)) % 1000000}",
        'detector': finding.get('detector'),
        'severity': finding.get('severity'),
        'timestamp': finding.get('timestamp'),
        'description': finding.get('description'),
        'data': finding.get('data', {}),
        'event_count': finding.get('event_count', 0)
    }

    # Add recommendations if present
    recommendations = finding.get('recommendations', [])
    if recommendations:
        json_finding['recommendations'] = recommendations

    return json_finding


def format_event_json(event):
    """Format an event for JSON output"""
    # Clean up the event - remove None values and normalize
    json_event = {}

    # Standard fields
    standard_fields = [
        'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
        'protocol', 'event_type', 'message', 'severity'
    ]

    for field in standard_fields:
        value = event.get(field)
        if value is not None:
            json_event[field] = value

    # Add any additional fields from the original event
    for key, value in event.items():
        if key not in standard_fields and key != 'raw' and value is not None:
            json_event[key] = value

    # Add raw data if it exists and is requested
    raw_data = event.get('raw')
    if raw_data and isinstance(raw_data, dict):
        json_event['raw'] = raw_data

    return json_event


def calculate_statistics(events):
    """Calculate statistics for JSON output"""
    stats = {
        'total_events': len(events),
        'unique_source_ips': 0,
        'unique_destination_ips': 0,
        'protocols': {},
        'event_types': {},
        'time_span_seconds': 0
    }

    if not events:
        return stats

    # Collect unique IPs
    src_ips = set()
    dst_ips = set()
    protocols = {}
    event_types = {}
    timestamps = []

    for event in events:
        # Source IPs
        src_ip = event.get('src_ip')
        if src_ip:
            src_ips.add(src_ip)

        # Destination IPs
        dst_ip = event.get('dst_ip')
        if dst_ip:
            dst_ips.add(dst_ip)

        # Protocols
        protocol = event.get('protocol')
        if protocol:
            protocols[protocol] = protocols.get(protocol, 0) + 1

        # Event types
        event_type = event.get('event_type')
        if event_type:
            event_types[event_type] = event_types.get(event_type, 0) + 1

        # Timestamps
        timestamp = event.get('timestamp')
        if timestamp:
            timestamps.append(timestamp)

    stats['unique_source_ips'] = len(src_ips)
    stats['unique_destination_ips'] = len(dst_ips)
    stats['protocols'] = protocols
    stats['event_types'] = event_types

    # Calculate time span
    if len(timestamps) > 1:
        timestamps.sort()
        try:
            from datetime import datetime
            first = datetime.fromisoformat(timestamps[0].replace('Z', '+00:00'))
            last = datetime.fromisoformat(timestamps[-1].replace('Z', '+00:00'))
            stats['time_span_seconds'] = (last - first).total_seconds()
        except:
            pass

    return stats


def get_time_range(events):
    """Get time range from events for JSON output"""
    if not events:
        return None

    timestamps = []
    for event in events:
        ts = event.get('timestamp')
        if ts:
            timestamps.append(ts)

    if not timestamps:
        return None

    timestamps.sort()
    return {
        'start': timestamps[0],
        'end': timestamps[-1],
        'events': len(timestamps)
    }