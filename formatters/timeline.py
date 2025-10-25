"""
SALAT v2 - Timeline Generator
Generate timeline visualizations of security findings
"""

import re
from datetime import datetime


def generate_timeline(findings, timeline_format, args):
    """
    Generate timeline visualization

    Args:
        findings: List of security findings
        timeline_format: 'ascii', 'html', or 'both'
        args: Command-line arguments

    Returns:
        Timeline output file path (if file was created)
    """
    if not findings:
        print("No findings to generate timeline")
        return None

    # Parse findings for timeline events
    timeline_events = parse_findings_for_timeline(findings)

    if not timeline_events:
        print("No timeline data available from findings")
        return None

    output_file = None

    if timeline_format in ['ascii', 'both']:
        generate_ascii_timeline(timeline_events)

    if timeline_format in ['html', 'both']:
        output_file = generate_html_timeline(timeline_events, args)

    return output_file


def parse_findings_for_timeline(findings):
    """Parse findings to extract timeline events"""
    events = []

    for finding in findings:
        data = finding.get('data', {})
        detector = finding.get('detector', '')
        severity = finding.get('severity', 'medium')

        # Extract timeline information
        event = {
            'type': detector,
            'severity': severity,
            'timestamp': finding.get('timestamp'),
            'source_ip': data.get('source_ip', 'Unknown'),
            'description': '',
            'details': data
        }

        # Build description based on detector type
        if 'brute force' in detector.lower():
            attempts = data.get('failed_attempts', 0)
            time_range = data.get('time_range', '')
            event['description'] = f"{attempts} failed authentication attempts"
            event['time_span'] = time_range

        elif 'port scan' in detector.lower():
            ports = data.get('unique_ports', 0)
            scan_type = data.get('scan_type', 'scan')
            event['description'] = f"{scan_type}: {ports} unique ports"
            event['time_span'] = data.get('time_range', '')

        events.append(event)

    return events


def generate_ascii_timeline(events):
    """Generate ASCII timeline in terminal"""
    print("\n" + "="*60)
    print("SECURITY EVENT TIMELINE")
    print("="*60)

    # Sort events by severity and timestamp
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    sorted_events = sorted(events, key=lambda x: (
        severity_order.get(x['severity'], 4),
        x['timestamp'] or ''
    ))

    for i, event in enumerate(sorted_events, 1):
        # Severity indicator
        severity_icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢'
        }
        icon = severity_icons.get(event['severity'], '⚪')

        print(f"\n{icon} Event {i}: {event['type']}")
        print(f"   ├─ Severity: {event['severity'].upper()}")
        print(f"   ├─ Source: {event['source_ip']}")

        if event['timestamp']:
            print(f"   ├─ Time: {event['timestamp']}")

        print(f"   └─ Details: {event['description']}")

    # Timeline distribution
    print("\n" + "-"*60)
    print("EVENT DISTRIBUTION")
    print("-"*60)

    # Count by type and severity
    type_counts = {}
    severity_counts = {}

    for event in events:
        event_type = event['type']
        severity = event['severity']

        type_counts[event_type] = type_counts.get(event_type, 0) + 1
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    # Display type distribution
    max_count = max(type_counts.values()) if type_counts else 1
    for event_type, count in sorted(type_counts.items()):
        bar_length = int((count / max_count) * 40)
        bar = '█' * bar_length
        print(f"{event_type:20} {bar} ({count})")

    # Display severity summary
    print(f"\nSeverity Summary:")
    for severity in ['critical', 'high', 'medium', 'low']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            print(f"  {severity.title()}: {count}")

    print("="*60 + "\n")


def generate_html_timeline(events, args):
    """Generate interactive HTML timeline"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f'timeline_{timestamp}.html'

    html_content = build_timeline_html(events, args)

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return output_file
    except Exception as e:
        print(f"Error creating HTML timeline: {e}")
        return None


def build_timeline_html(events, args):
    """Build HTML timeline content"""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SALAT v2 Security Timeline</title>
    {get_timeline_styles()}
</head>
<body>
    <div class="container">
        {build_timeline_header(args)}
        {build_timeline_content(events)}
        {build_timeline_footer()}
    </div>
    {get_timeline_scripts()}
</body>
</html>"""


def build_timeline_header(args):
    """Build timeline header"""
    return f"""
    <div class="header">
        <h1>🕒 Security Event Timeline</h1>
        <p class="subtitle">SALAT v2 - Temporal Analysis</p>
        <div class="file-info">
            <span>📁 {args.log_file}</span>
            <span>📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
        </div>
    </div>"""


def build_timeline_content(events):
    """Build timeline events content"""
    if not events:
        return "<div class='no-events'>No timeline events to display</div>"

    # Sort events by timestamp
    sorted_events = sorted(events, key=lambda x: x['timestamp'] or '')

    timeline_html = "<div class='timeline'>"

    for i, event in enumerate(sorted_events):
        timeline_html += build_timeline_event_html(event, i + 1)

    timeline_html += "</div>"

    # Add summary statistics
    stats_html = build_timeline_stats(events)

    return f"""
    <div class="timeline-section">
        <h2>Timeline Events</h2>
        {timeline_html}
        {stats_html}
    </div>"""


def build_timeline_event_html(event, index):
    """Build HTML for a single timeline event"""
    severity = event['severity']
    timestamp = event['timestamp'] or 'Unknown'

    return f"""
    <div class="timeline-event {severity}">
        <div class="timeline-marker">
            <div class="marker-icon {severity}"></div>
            <div class="marker-line"></div>
        </div>
        <div class="timeline-content">
            <div class="event-header">
                <h3>{event['type']}</h3>
                <span class="severity-badge {severity}">{severity.upper()}</span>
            </div>
            <div class="event-details">
                <div class="detail-row">
                    <span class="label">Time:</span>
                    <span class="value">{timestamp}</span>
                </div>
                <div class="detail-row">
                    <span class="label">Source:</span>
                    <span class="value">{event['source_ip']}</span>
                </div>
                <div class="detail-row">
                    <span class="label">Description:</span>
                    <span class="value">{event['description']}</span>
                </div>
            </div>
        </div>
    </div>"""


def build_timeline_stats(events):
    """Build timeline statistics"""
    # Count by severity
    severity_counts = {}
    type_counts = {}

    for event in events:
        severity = event['severity']
        event_type = event['type']

        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        type_counts[event_type] = type_counts.get(event_type, 0) + 1

    stats_html = """
    <div class="timeline-stats">
        <h3>Timeline Statistics</h3>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{}</div>
                <div class="stat-label">Total Events</div>
            </div>""".format(len(events))

    # Add severity stats
    for severity in ['critical', 'high', 'medium', 'low']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            stats_html += f"""
            <div class="stat-card {severity}">
                <div class="stat-number">{count}</div>
                <div class="stat-label">{severity.title()}</div>
            </div>"""

    stats_html += "</div></div>"
    return stats_html


def build_timeline_footer():
    """Build timeline footer"""
    return f"""
    <div class="footer">
        <p>Generated by SALAT v2 - Security Timeline Analysis</p>
        <p>Created on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
    </div>"""


def get_timeline_styles():
    """Get CSS styles for timeline"""
    return """
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
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
            flex-wrap: wrap;
            gap: 10px;
        }

        .file-info span {
            background: rgba(255,255,255,0.2);
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
        }

        .timeline-section {
            padding: 30px;
        }

        .timeline {
            position: relative;
            margin: 30px 0;
        }

        .timeline-event {
            display: flex;
            margin-bottom: 30px;
            position: relative;
        }

        .timeline-marker {
            display: flex;
            flex-direction: column;
            align-items: center;
            margin-right: 20px;
            min-width: 20px;
        }

        .marker-icon {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            border: 3px solid white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            z-index: 2;
        }

        .marker-icon.critical {
            background: #dc3545;
        }

        .marker-icon.high {
            background: #fd7e14;
        }

        .marker-icon.medium {
            background: #ffc107;
        }

        .marker-icon.low {
            background: #28a745;
        }

        .marker-line {
            width: 2px;
            height: 60px;
            background: #dee2e6;
            margin-top: 10px;
        }

        .timeline-event:last-child .marker-line {
            display: none;
        }

        .timeline-content {
            flex: 1;
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid;
        }

        .timeline-content.critical {
            border-left-color: #dc3545;
        }

        .timeline-content.high {
            border-left-color: #fd7e14;
        }

        .timeline-content.medium {
            border-left-color: #ffc107;
        }

        .timeline-content.low {
            border-left-color: #28a745;
        }

        .event-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .event-header h3 {
            color: #333;
        }

        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.8em;
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

        .event-details {
            font-size: 0.9em;
        }

        .detail-row {
            display: flex;
            margin-bottom: 8px;
        }

        .label {
            font-weight: bold;
            min-width: 100px;
            color: #6c757d;
        }

        .value {
            color: #333;
            font-family: monospace;
        }

        .timeline-stats {
            margin-top: 40px;
            padding-top: 30px;
            border-top: 2px solid #dee2e6;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .stat-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border-left: 4px solid #6c757d;
        }

        .stat-card.critical {
            border-left-color: #dc3545;
        }

        .stat-card.high {
            border-left-color: #fd7e14;
        }

        .stat-card.medium {
            border-left-color: #ffc107;
        }

        .stat-card.low {
            border-left-color: #28a745;
        }

        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }

        .stat-label {
            color: #6c757d;
            margin-top: 5px;
        }

        .footer {
            background: #343a40;
            color: white;
            text-align: center;
            padding: 20px;
        }

        .no-events {
            text-align: center;
            padding: 40px;
            color: #6c757d;
            font-style: italic;
        }

        @media (max-width: 768px) {
            .file-info {
                flex-direction: column;
            }

            .event-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }

            .timeline-event {
                flex-direction: column;
            }

            .timeline-marker {
                margin-right: 0;
                margin-bottom: 15px;
            }

            .marker-line {
                width: 60px;
                height: 2px;
                margin-top: 0;
                margin-left: 10px;
            }
        }
    </style>"""


def get_timeline_scripts():
    """Get JavaScript for timeline interactivity"""
    return """
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Add smooth scrolling to timeline events
            const events = document.querySelectorAll('.timeline-event');

            // Add click handlers for timeline events
            events.forEach(function(event, index) {
                event.addEventListener('click', function() {
                    // Add a visual indicator when clicked
                    event.style.transform = 'scale(1.02)';
                    setTimeout(function() {
                        event.style.transform = 'scale(1)';
                    }, 200);
                });
            });

            // Add animation on scroll
            const observer = new IntersectionObserver(function(entries) {
                entries.forEach(function(entry) {
                    if (entry.isIntersecting) {
                        entry.target.style.opacity = '1';
                        entry.target.style.transform = 'translateX(0)';
                    }
                });
            });

            events.forEach(function(event) {
                event.style.opacity = '0';
                event.style.transform = 'translateX(-20px)';
                event.style.transition = 'opacity 0.5s, transform 0.5s';
                observer.observe(event);
            });
        });
    </script>"""