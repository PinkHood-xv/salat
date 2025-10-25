"""
SALAT v2 - CSV Output Formatter
Format analysis results as CSV for spreadsheet analysis
"""

import csv
import io
from datetime import datetime
from lib.detectors import get_findings_summary


def format_csv(events, findings, args):
    """
    Format output as CSV

    Args:
        events: List of filtered events
        findings: List of detection findings
        args: Parsed command-line arguments

    Returns:
        CSV formatted string
    """
    output = io.StringIO()

    # Write findings CSV if there are findings
    if findings:
        output.write("FINDINGS:\n")
        write_findings_csv(output, findings)
        output.write("\n\n")

    # Write events CSV (unless summary only)
    if not args.summary_only and events:
        output.write("EVENTS:\n")
        write_events_csv(output, events, args.limit)

    return output.getvalue()


def write_findings_csv(output, findings):
    """Write findings to CSV format"""
    fieldnames = [
        'detector',
        'severity',
        'timestamp',
        'source_ip',
        'target_info',
        'event_count',
        'details',
        'recommendations'
    ]

    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for finding in findings:
        data = finding.get('data', {})
        recommendations = finding.get('recommendations', [])

        # Extract key information based on detector type
        source_ip = data.get('source_ip', '')
        target_info = ''
        details = ''

        detector = finding.get('detector', '').lower()
        if 'brute force' in detector:
            target_info = data.get('targets', '')
            details = f"Failed attempts: {data.get('failed_attempts', 0)}, Time range: {data.get('time_range', '')}"

        elif 'port scan' in detector:
            target_info = f"{data.get('target_hosts', 0)} hosts"
            details = f"Scan type: {data.get('scan_type', '')}, Unique ports: {data.get('unique_ports', 0)}"

        row = {
            'detector': finding.get('detector', ''),
            'severity': finding.get('severity', ''),
            'timestamp': finding.get('timestamp', ''),
            'source_ip': source_ip,
            'target_info': target_info,
            'event_count': finding.get('event_count', 0),
            'details': details,
            'recommendations': '; '.join(recommendations[:3])  # First 3 recommendations
        }

        writer.writerow(row)


def write_events_csv(output, events, limit=None):
    """Write events to CSV format"""
    if not events:
        return

    # Determine fieldnames based on available data
    all_fields = set()
    for event in events:
        all_fields.update(event.keys())

    # Remove 'raw' field as it's not suitable for CSV
    all_fields.discard('raw')

    # Define preferred field order
    preferred_order = [
        'timestamp',
        'event_type',
        'src_ip',
        'dst_ip',
        'src_port',
        'dst_port',
        'protocol',
        'message',
        'severity'
    ]

    # Build fieldnames with preferred order first, then remaining fields
    fieldnames = []
    for field in preferred_order:
        if field in all_fields:
            fieldnames.append(field)
            all_fields.remove(field)

    # Add remaining fields
    fieldnames.extend(sorted(all_fields))

    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()

    # Limit events if specified
    events_to_write = events[:limit] if limit else events

    for event in events_to_write:
        # Clean the event data for CSV
        clean_event = {}
        for field in fieldnames:
            value = event.get(field, '')
            # Convert to string and handle None values
            if value is None:
                clean_event[field] = ''
            else:
                # Truncate long messages for CSV readability
                if field == 'message' and isinstance(value, str) and len(value) > 200:
                    clean_event[field] = value[:197] + '...'
                else:
                    clean_event[field] = str(value)

        writer.writerow(clean_event)


def format_events_only_csv(events, limit=None):
    """Format only events as CSV (utility function)"""
    output = io.StringIO()
    write_events_csv(output, events, limit)
    return output.getvalue()


def format_findings_only_csv(findings):
    """Format only findings as CSV (utility function)"""
    output = io.StringIO()
    write_findings_csv(output, findings)
    return output.getvalue()