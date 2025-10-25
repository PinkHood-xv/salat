"""
SALAT v2 - HTML Output Formatter
Generate interactive HTML reports
"""

from datetime import datetime
from lib.filters import get_filter_summary
from lib.detectors import get_findings_summary


def format_html(events, findings, args):
    """
    Format output as HTML report

    Args:
        events: List of filtered events
        findings: List of detection findings
        args: Parsed command-line arguments

    Returns:
        HTML formatted string
    """
    # Get summary data
    findings_summary = get_findings_summary(findings) if findings else {}
    filters = get_filter_summary(args)

    # Build HTML
    html_content = build_html_template(
        events=events,
        findings=findings,
        findings_summary=findings_summary,
        filters=filters,
        args=args
    )

    return html_content


def build_html_template(events, findings, findings_summary, filters, args):
    """Build complete HTML template"""

    # Calculate statistics
    stats = calculate_html_stats(events)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SALAT v2 Analysis Report</title>
    {get_html_styles()}
</head>
<body>
    <div class="container">
        {build_header(args)}
        {build_summary_section(events, findings_summary, stats, filters)}
        {build_findings_section(findings) if findings else ''}
        {build_events_section(events, args) if not args.summary_only else ''}
        {build_footer()}
    </div>
    {get_html_scripts()}
</body>
</html>"""

    return html


def build_header(args):
    """Build HTML header section"""
    return f"""
    <div class="header">
        <h1>🛡️ SALAT v2 Analysis Report</h1>
        <p class="subtitle">SOC Analyst Log Analysis Toolkit</p>
        <div class="file-info">
            <span class="file-name">📁 {args.log_file}</span>
            <span class="timestamp">📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
        </div>
    </div>"""


def build_summary_section(events, findings_summary, stats, filters):
    """Build summary statistics section"""
    findings_count = findings_summary.get('total', 0)

    # Severity counts
    severity_badges = ""
    for severity in ['critical', 'high', 'medium', 'low']:
        count = findings_summary.get('by_severity', {}).get(severity, 0)
        if count > 0:
            severity_badges += f'<span class="severity-badge {severity}">{severity.title()}: {count}</span>'

    # Filters applied
    filters_html = ""
    if filters:
        filters_html = "<div class='filters-applied'><h4>Filters Applied:</h4><ul>"
        for filter_desc in filters:
            filters_html += f"<li>{filter_desc}</li>"
        filters_html += "</ul></div>"

    return f"""
    <div class="summary-section">
        <h2>📊 Analysis Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-number">{len(events)}</div>
                <div class="summary-label">Events Analyzed</div>
            </div>
            <div class="summary-card">
                <div class="summary-number">{findings_count}</div>
                <div class="summary-label">Security Issues</div>
            </div>
            <div class="summary-card">
                <div class="summary-number">{stats['unique_ips']}</div>
                <div class="summary-label">Unique IPs</div>
            </div>
            <div class="summary-card">
                <div class="summary-number">{stats['protocols_count']}</div>
                <div class="summary-label">Protocols</div>
            </div>
        </div>

        {f'<div class="severity-summary">{severity_badges}</div>' if severity_badges else ''}
        {filters_html}
    </div>"""


def build_findings_section(findings):
    """Build security findings section"""
    if not findings:
        return ""

    findings_html = ""
    for i, finding in enumerate(findings, 1):
        findings_html += format_finding_html(finding, i)

    return f"""
    <div class="findings-section">
        <h2>🚨 Security Findings</h2>
        <div class="findings-container">
            {findings_html}
        </div>
    </div>"""


def format_finding_html(finding, index):
    """Format a single finding as HTML"""
    severity = finding.get('severity', 'unknown')
    detector = finding.get('detector', 'Unknown')
    data = finding.get('data', {})
    recommendations = finding.get('recommendations', [])

    # Build details based on detector type
    details_html = ""
    if 'brute force' in detector.lower():
        details_html = f"""
        <div class="finding-details">
            <div class="detail-row">
                <span class="detail-label">Source IP:</span>
                <span class="detail-value">{data.get('source_ip', 'Unknown')}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Failed Attempts:</span>
                <span class="detail-value">{data.get('failed_attempts', 0)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Time Range:</span>
                <span class="detail-value">{data.get('time_range', 'Unknown')}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Attack Rate:</span>
                <span class="detail-value">{data.get('attack_rate', 'Unknown')}</span>
            </div>
        </div>"""

    elif 'port scan' in detector.lower():
        details_html = f"""
        <div class="finding-details">
            <div class="detail-row">
                <span class="detail-label">Source IP:</span>
                <span class="detail-value">{data.get('source_ip', 'Unknown')}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Scan Type:</span>
                <span class="detail-value">{data.get('scan_type', 'Unknown')}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Unique Ports:</span>
                <span class="detail-value">{data.get('unique_ports', 0)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Target Hosts:</span>
                <span class="detail-value">{data.get('target_hosts', 0)}</span>
            </div>
        </div>"""

    # Recommendations
    recommendations_html = ""
    if recommendations:
        recommendations_html = "<div class='recommendations'><h4>Recommendations:</h4><ul>"
        for rec in recommendations[:5]:  # Show first 5
            recommendations_html += f"<li>{rec}</li>"
        recommendations_html += "</ul></div>"

    return f"""
    <div class="finding-card {severity}">
        <div class="finding-header">
            <h3 class="finding-title">
                <span class="severity-icon {severity}">●</span>
                {detector}
            </h3>
            <span class="severity-badge {severity}">{severity.upper()}</span>
        </div>
        {details_html}
        {recommendations_html}
    </div>"""


def build_events_section(events, args):
    """Build events section"""
    if not events:
        return ""

    # Limit events for performance
    events_to_show = events[:100] if len(events) > 100 else events
    show_limit_note = len(events) > 100

    events_html = ""
    for i, event in enumerate(events_to_show, 1):
        events_html += format_event_html(event, i)

    limit_note = ""
    if show_limit_note:
        limit_note = f'<p class="limit-note">Showing first 100 of {len(events)} events</p>'

    return f"""
    <div class="events-section">
        <h2>📋 Event Details</h2>
        {limit_note}
        <div class="events-container">
            {events_html}
        </div>
    </div>"""


def format_event_html(event, index):
    """Format a single event as HTML"""
    timestamp = event.get('timestamp', 'Unknown')
    event_type = event.get('event_type', 'unknown')
    src_ip = event.get('src_ip', '')
    dst_ip = event.get('dst_ip', '')
    protocol = event.get('protocol', '')
    message = event.get('message', '')

    # Build connection info
    connection_info = ""
    if src_ip or dst_ip:
        src_part = src_ip or 'unknown'
        dst_part = dst_ip or 'unknown'

        src_port = event.get('src_port')
        dst_port = event.get('dst_port')
        if src_port:
            src_part += f":{src_port}"
        if dst_port:
            dst_part += f":{dst_port}"

        connection_info = f"{src_part} → {dst_part}"

    return f"""
    <div class="event-card">
        <div class="event-header">
            <span class="event-index">#{index}</span>
            <span class="event-type">{event_type}</span>
            <span class="event-timestamp">{timestamp}</span>
        </div>
        <div class="event-details">
            {f'<div class="event-connection">{connection_info}</div>' if connection_info else ''}
            {f'<div class="event-protocol">Protocol: {protocol}</div>' if protocol else ''}
            {f'<div class="event-message">{message[:200]}{"..." if len(message) > 200 else ""}</div>' if message else ''}
        </div>
    </div>"""


def build_footer():
    """Build HTML footer"""
    return f"""
    <div class="footer">
        <p>Generated by SALAT v2 - SOC Analyst Log Analysis Toolkit</p>
        <p>Report generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
    </div>"""


def calculate_html_stats(events):
    """Calculate statistics for HTML display"""
    unique_ips = set()
    protocols = set()

    for event in events:
        src_ip = event.get('src_ip')
        dst_ip = event.get('dst_ip')
        if src_ip:
            unique_ips.add(src_ip)
        if dst_ip:
            unique_ips.add(dst_ip)

        protocol = event.get('protocol')
        if protocol:
            protocols.add(protocol)

    return {
        'unique_ips': len(unique_ips),
        'protocols_count': len(protocols)
    }


def get_html_styles():
    """Get CSS styles for HTML report"""
    return """
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }

        .file-info {
            margin-top: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
        }

        .file-name, .timestamp {
            background: rgba(255,255,255,0.2);
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
        }

        .summary-section {
            padding: 30px;
            background: #f8f9fa;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .summary-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }

        .summary-label {
            color: #6c757d;
            margin-top: 5px;
        }

        .severity-summary {
            margin: 20px 0;
        }

        .severity-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            margin: 5px;
            font-size: 0.9em;
        }

        .severity-badge.critical {
            background: #dc3545;
        }

        .severity-badge.high {
            background: #fd7e14;
        }

        .severity-badge.medium {
            background: #ffc107;
            color: #333;
        }

        .severity-badge.low {
            background: #28a745;
        }

        .findings-section, .events-section {
            padding: 30px;
        }

        .finding-card {
            background: white;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid;
        }

        .finding-card.critical {
            border-left-color: #dc3545;
        }

        .finding-card.high {
            border-left-color: #fd7e14;
        }

        .finding-card.medium {
            border-left-color: #ffc107;
        }

        .finding-card.low {
            border-left-color: #28a745;
        }

        .finding-header {
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #eee;
        }

        .finding-title {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .severity-icon.critical {
            color: #dc3545;
        }

        .severity-icon.high {
            color: #fd7e14;
        }

        .severity-icon.medium {
            color: #ffc107;
        }

        .severity-icon.low {
            color: #28a745;
        }

        .finding-details, .recommendations {
            padding: 20px;
        }

        .detail-row {
            display: flex;
            margin-bottom: 10px;
        }

        .detail-label {
            font-weight: bold;
            min-width: 150px;
            color: #6c757d;
        }

        .detail-value {
            font-family: monospace;
            color: #333;
        }

        .event-card {
            background: white;
            border-radius: 8px;
            margin-bottom: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }

        .event-header {
            padding: 15px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .event-index {
            font-weight: bold;
            color: #6c757d;
        }

        .event-type {
            background: #e9ecef;
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 0.9em;
        }

        .event-timestamp {
            font-family: monospace;
            font-size: 0.9em;
            color: #6c757d;
        }

        .event-details {
            padding: 15px;
        }

        .event-connection, .event-protocol {
            margin-bottom: 8px;
            font-family: monospace;
        }

        .event-message {
            color: #6c757d;
            font-style: italic;
        }

        .filters-applied {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
        }

        .filters-applied ul {
            list-style-type: none;
            padding-left: 0;
        }

        .filters-applied li {
            padding: 5px 0;
            border-bottom: 1px solid #eee;
        }

        .footer {
            background: #343a40;
            color: white;
            text-align: center;
            padding: 20px;
        }

        .limit-note {
            background: #fff3cd;
            color: #856404;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
        }

        @media (max-width: 768px) {
            .file-info {
                flex-direction: column;
                gap: 10px;
            }

            .finding-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }

            .event-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
        }
    </style>"""


def get_html_scripts():
    """Get JavaScript for HTML report"""
    return """
    <script>
        // Add any interactive functionality here
        document.addEventListener('DOMContentLoaded', function() {
            // Simple click to copy functionality for IP addresses
            document.querySelectorAll('.detail-value').forEach(function(element) {
                if (element.textContent.match(/\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/)) {
                    element.style.cursor = 'pointer';
                    element.title = 'Click to copy IP address';
                    element.addEventListener('click', function() {
                        navigator.clipboard.writeText(element.textContent);
                    });
                }
            });
        });
    </script>"""