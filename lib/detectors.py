"""
SALAT v2 - Detection Engine
Orchestrate detection modules and manage findings
"""


def run_detections(events, args):
    """
    Run specified detection modules

    Args:
        events: List of normalized events
        args: Parsed command-line arguments

    Returns:
        List of findings from all detectors
    """
    if not args.detect:
        return []

    findings = []
    detect_types = parse_detect_types(args.detect)

    # Run Brute Force Detection
    if 'brute-force' in detect_types or 'all' in detect_types:
        try:
            from detectors.brute_force import BruteForceDetector
            detector = BruteForceDetector(
                threshold=args.threshold,
                time_window=args.time_window
            )
            bf_findings = detector.detect(events)
            findings.extend(bf_findings)
        except Exception as e:
            print(f"Warning: Brute force detection failed: {e}")

    # Run Port Scan Detection
    if 'port-scan' in detect_types or 'all' in detect_types:
        try:
            from detectors.port_scan import PortScanDetector
            detector = PortScanDetector(
                threshold=args.threshold if args.threshold != 5 else 10,  # Different default for port scans
                time_window=args.time_window if args.time_window != 300 else 60  # Different default for port scans
            )
            ps_findings = detector.detect(events)
            findings.extend(ps_findings)
        except Exception as e:
            print(f"Warning: Port scan detection failed: {e}")

    # Sort findings by severity and timestamp
    findings = sort_findings(findings)

    return findings


def parse_detect_types(detect_string):
    """
    Parse detection types from command line argument

    Args:
        detect_string: Comma-separated detection types

    Returns:
        List of detection type strings
    """
    if not detect_string:
        return []

    # Split by comma and clean up
    types = [t.strip().lower() for t in detect_string.split(',')]

    # Normalize aliases
    normalized_types = []
    for dtype in types:
        if dtype in ['all', '*']:
            normalized_types.append('all')
        elif dtype in ['brute-force', 'bruteforce', 'brute_force', 'bf']:
            normalized_types.append('brute-force')
        elif dtype in ['port-scan', 'portscan', 'port_scan', 'ps', 'scan']:
            normalized_types.append('port-scan')
        else:
            # Pass through unknown types (for future extensibility)
            normalized_types.append(dtype)

    return normalized_types


def sort_findings(findings):
    """
    Sort findings by severity and timestamp

    Args:
        findings: List of findings

    Returns:
        Sorted list of findings
    """
    # Severity order (higher priority first)
    severity_order = {
        'critical': 0,
        'high': 1,
        'medium': 2,
        'low': 3,
        'info': 4
    }

    def sort_key(finding):
        severity = finding.get('severity', 'info')
        severity_priority = severity_order.get(severity, 99)

        # Use timestamp as secondary sort (newest first)
        timestamp = finding.get('timestamp', '')

        return (severity_priority, timestamp)

    return sorted(findings, key=sort_key)


def get_findings_summary(findings):
    """
    Get summary statistics for findings

    Args:
        findings: List of findings

    Returns:
        Dict with summary statistics
    """
    if not findings:
        return {
            'total': 0,
            'by_severity': {},
            'by_detector': {}
        }

    # Count by severity
    by_severity = {}
    for finding in findings:
        severity = finding.get('severity', 'unknown')
        by_severity[severity] = by_severity.get(severity, 0) + 1

    # Count by detector
    by_detector = {}
    for finding in findings:
        detector = finding.get('detector', 'unknown')
        by_detector[detector] = by_detector.get(detector, 0) + 1

    return {
        'total': len(findings),
        'by_severity': by_severity,
        'by_detector': by_detector
    }


def filter_findings_by_severity(findings, min_severity='low'):
    """
    Filter findings by minimum severity level

    Args:
        findings: List of findings
        min_severity: Minimum severity level to include

    Returns:
        Filtered list of findings
    """
    severity_levels = ['low', 'medium', 'high', 'critical']

    try:
        min_index = severity_levels.index(min_severity.lower())
    except ValueError:
        return findings

    filtered = []
    for finding in findings:
        severity = finding.get('severity', 'low').lower()
        try:
            severity_index = severity_levels.index(severity)
            if severity_index >= min_index:
                filtered.append(finding)
        except ValueError:
            # Unknown severity, include it
            filtered.append(finding)

    return filtered


def get_available_detectors():
    """
    Get list of available detection modules

    Returns:
        Dict mapping detector names to descriptions
    """
    detectors = {
        'brute-force': {
            'name': 'Brute Force Attack Detection',
            'description': 'Detects multiple failed authentication attempts from the same source',
            'default_threshold': 5,
            'default_time_window': 300
        },
        'port-scan': {
            'name': 'Port Scan Detection',
            'description': 'Detects reconnaissance activity via port scanning',
            'default_threshold': 10,
            'default_time_window': 60
        }
    }

    return detectors