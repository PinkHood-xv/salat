"""
SALAT v2 - Text Output Formatter
Format analysis results as plain text
"""

from lib.filters import get_filter_summary
from lib.detectors import get_findings_summary


def format_text(events, findings, args):
    """
    Format output as plain text

    Args:
        events: List of filtered events
        findings: List of detection findings
        args: Parsed command-line arguments

    Returns:
        Formatted text string
    """
    output = []

    # Don't repeat header if already shown
    if not args.quiet:
        # File information
        output.append(f"File: {args.log_file}")
        if args.format:
            output.append(f"Format: {args.format.upper()}")

        # Event count
        output.append(f"Events analyzed: {len(events)}")

        # Time range (if we can determine it)
        time_range = get_time_range(events)
        if time_range:
            output.append(f"Time range: {time_range}")

    # Filters applied
    filters = get_filter_summary(args)
    if filters and not args.quiet:
        output.append("\nFilters Applied:")
        for filter_desc in filters:
            output.append(f"  • {filter_desc}")

    # Results summary
    if not args.summary_only:
        output.append(f"\nResults: {len(events)} events matched")

    # Detection findings
    if findings:
        output.append("\nDETECTIONS:")
        output.append("-" * 50)

        findings_summary = get_findings_summary(findings)

        # Summary line
        if not args.quiet:
            severity_counts = []
            for severity in ['critical', 'high', 'medium', 'low']:
                count = findings_summary['by_severity'].get(severity, 0)
                if count > 0:
                    severity_counts.append(f"{severity.title()}: {count}")

            if severity_counts:
                output.append(f"Found {findings_summary['total']} issues ({', '.join(severity_counts)})")
            output.append("")

        # Individual findings
        for i, finding in enumerate(findings, 1):
            output.append(format_finding(finding, i, args.verbose))

    elif args.detect:
        output.append("\n✅ No security anomalies detected.")

    # Event details (if verbose and not summary-only)
    if args.verbose and not args.summary_only and events:
        output.append("\nEVENT DETAILS:")
        output.append("-" * 50)

        # Limit events if specified
        events_to_show = events
        if args.limit:
            events_to_show = events[:args.limit]
            if len(events) > args.limit:
                output.append(f"Showing first {args.limit} of {len(events)} events:")
                output.append("")

        for i, event in enumerate(events_to_show, 1):
            output.append(format_event(event, i))

    # Summary statistics
    if not args.quiet or args.summary_only:
        output.append("\nSUMMARY:")
        output.append("-" * 30)
        output.append(f"Total events: {len(events)}")

        if findings:
            output.append(f"Detections: {len(findings)}")
            findings_summary = get_findings_summary(findings)
            for severity, count in findings_summary['by_severity'].items():
                output.append(f"  {severity.title()}: {count}")

        # Unique IPs
        src_ips = len(set(e.get('src_ip') for e in events if e.get('src_ip')))
        dst_ips = len(set(e.get('dst_ip') for e in events if e.get('dst_ip')))
        if src_ips > 0:
            output.append(f"Unique source IPs: {src_ips}")
        if dst_ips > 0:
            output.append(f"Unique destination IPs: {dst_ips}")

    return '\n'.join(output)


def format_finding(finding, index, verbose=False):
    """Format a single finding for text output"""
    output = []

    severity = finding.get('severity', 'unknown').upper()
    detector = finding.get('detector', 'Unknown')
    data = finding.get('data', {})

    # Severity indicator
    severity_icons = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🟢'
    }
    icon = severity_icons.get(severity, '⚪')

    # Finding header
    output.append(f"{icon} [{severity}] {detector}")

    # Key details based on detector type
    if 'brute force' in detector.lower():
        source_ip = data.get('source_ip', 'Unknown')
        attempts = data.get('failed_attempts', 0)
        time_range = data.get('time_range', 'Unknown')
        targets = data.get('targets', 'Unknown')

        output.append(f"   Source: {source_ip}")
        output.append(f"   Failed attempts: {attempts}")
        output.append(f"   Time range: {time_range}")
        output.append(f"   Targets: {targets}")

        if verbose:
            attack_rate = data.get('attack_rate', 'Unknown')
            output.append(f"   Attack rate: {attack_rate}")

    elif 'port scan' in detector.lower():
        source_ip = data.get('source_ip', 'Unknown')
        scan_type = data.get('scan_type', 'Unknown')
        unique_ports = data.get('unique_ports', 0)
        target_hosts = data.get('target_hosts', 0)
        ports_sample = data.get('ports_scanned', 'Unknown')

        output.append(f"   Source: {source_ip}")
        output.append(f"   Scan type: {scan_type}")
        output.append(f"   Unique ports: {unique_ports}")
        output.append(f"   Target hosts: {target_hosts}")

        if verbose:
            output.append(f"   Ports: {ports_sample}")
            scan_rate = data.get('scan_rate', 'Unknown')
            output.append(f"   Scan rate: {scan_rate}")

    # Recommendations (if verbose)
    if verbose:
        recommendations = finding.get('recommendations', [])
        if recommendations:
            output.append("   Recommendations:")
            for rec in recommendations[:3]:  # Show first 3
                output.append(f"     • {rec}")

    output.append("")  # Empty line between findings
    return '\n'.join(output)


def format_event(event, index):
    """Format a single event for text output"""
    output = []

    # Event header
    timestamp = event.get('timestamp', 'Unknown')
    event_type = event.get('event_type', 'unknown')
    output.append(f"Event {index}: {event_type}")

    # Key fields
    output.append(f"  Time: {timestamp}")

    src_ip = event.get('src_ip')
    dst_ip = event.get('dst_ip')
    if src_ip or dst_ip:
        src_part = src_ip or 'unknown'
        dst_part = dst_ip or 'unknown'

        # Include ports if available
        src_port = event.get('src_port')
        dst_port = event.get('dst_port')
        if src_port:
            src_part += f":{src_port}"
        if dst_port:
            dst_part += f":{dst_port}"

        output.append(f"  Connection: {src_part} → {dst_part}")

    protocol = event.get('protocol')
    if protocol:
        output.append(f"  Protocol: {protocol}")

    message = event.get('message')
    if message:
        # Truncate long messages
        if len(message) > 100:
            message = message[:97] + "..."
        output.append(f"  Message: {message}")

    output.append("")  # Empty line between events
    return '\n'.join(output)


def get_time_range(events):
    """Get time range from events"""
    if not events:
        return None

    timestamps = []
    for event in events:
        ts_str = event.get('timestamp')
        if ts_str:
            timestamps.append(ts_str)

    if not timestamps:
        return None

    timestamps.sort()
    first = timestamps[0]
    last = timestamps[-1]

    # If same timestamp, just show one
    if first == last:
        return first

    return f"{first} to {last}"