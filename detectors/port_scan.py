"""
SALAT v2 - Port Scan Detection
Detect port scanning and reconnaissance activity
"""

from collections import defaultdict
from .base import BaseDetector


class PortScanDetector(BaseDetector):
    """Detect port scanning activity"""

    def __init__(self, threshold=10, time_window=60, **kwargs):
        """
        Initialize port scan detector

        Args:
            threshold: Number of unique ports to trigger detection (default: 10)
            time_window: Time window in seconds (default: 60)
        """
        super().__init__(threshold, time_window, **kwargs)

    def get_detector_name(self):
        return "Port Scan"

    def get_detector_description(self):
        return "Detects reconnaissance activity via port scanning"

    def get_default_threshold(self):
        """Default threshold for port scan detection"""
        return 10

    def get_default_time_window(self):
        """Default time window for port scan detection (1 minute)"""
        return 60

    def detect(self, events):
        """
        Detect port scan patterns in events

        Args:
            events: List of normalized events

        Returns:
            List of findings
        """
        findings = []

        # Filter for connection attempt events
        connection_events = self.filter_connection_events(events)

        if not connection_events:
            return findings

        # Group by source IP
        ip_groups = self.group_events_by_field(connection_events, 'src_ip')

        # Analyze each IP's connection attempts
        for src_ip, connections in ip_groups.items():
            # Get unique destination ports
            unique_ports = self.get_unique_ports(connections)

            if len(unique_ports) >= self.threshold:
                # Check if within time window
                if self.within_time_window(connections):
                    finding = self.create_port_scan_finding(src_ip, connections, unique_ports)
                    findings.append(finding)

        return findings

    def filter_connection_events(self, events):
        """Filter events for connection attempts"""
        connection_events = []

        # Connection indicators
        connection_types = [
            'connection',
            'network_packet',
            'tcp_connection',
            'syn',
            'connection_attempt'
        ]

        for event in events:
            is_connection = False

            # Check event type
            event_type = str(event.get('event_type', '')).lower()
            if any(conn_type in event_type for conn_type in connection_types):
                is_connection = True

            # Check if event has destination port (indicates network activity)
            if not is_connection and event.get('dst_port'):
                is_connection = True

            # For TCP packets, look for SYN flags
            if not is_connection:
                protocol = str(event.get('protocol', '')).upper()
                if protocol == 'TCP':
                    # Check various ways TCP flags might be represented
                    tcp_flags = str(event.get('tcp_flags', '')).upper()
                    message = str(event.get('message', '')).upper()
                    if 'SYN' in tcp_flags or 'SYN' in message:
                        is_connection = True

            # Check for firewall drops (could indicate scanning)
            if not is_connection:
                message = str(event.get('message', '')).lower()
                event_type = str(event.get('event_type', '')).lower()
                if ('drop' in message or 'deny' in message or 'firewall_drop' in event_type) and event.get('dst_port'):
                    is_connection = True

            if is_connection:
                connection_events.append(event)

        return connection_events

    def get_unique_ports(self, connections):
        """Get unique destination ports from connections"""
        ports = set()

        for conn in connections:
            dst_port = conn.get('dst_port')
            if dst_port:
                try:
                    # Ensure port is valid
                    port_num = int(dst_port)
                    if 1 <= port_num <= 65535:
                        ports.add(port_num)
                except (ValueError, TypeError):
                    continue

        return ports

    def create_port_scan_finding(self, src_ip, connections, unique_ports):
        """Create port scan finding"""
        count = len(connections)
        port_count = len(unique_ports)

        # Get time range
        timestamps = [self.parse_timestamp(c.get('timestamp')) for c in connections]
        valid_timestamps = [ts for ts in timestamps if ts]

        if valid_timestamps:
            valid_timestamps.sort()
            first_attempt = valid_timestamps[0]
            last_attempt = valid_timestamps[-1]
            duration = (last_attempt - first_attempt).total_seconds()
            time_range = f"{first_attempt.strftime('%Y-%m-%d %H:%M:%S')} to {last_attempt.strftime('%Y-%m-%d %H:%M:%S')}"
        else:
            duration = 0
            time_range = "Unknown"

        # Get target hosts
        targets = self.get_unique_values(connections, 'dst_ip')
        target_count = len(targets)
        target_info = ', '.join(list(targets)[:3]) if targets else 'Unknown'
        if target_count > 3:
            target_info += f' (+{target_count-3} more)'

        # Determine scan type
        scan_type = self.determine_scan_type(connections, unique_ports)

        # Get port sample for display
        sorted_ports = sorted(list(unique_ports))
        port_sample = ', '.join(map(str, sorted_ports[:10]))
        if len(unique_ports) > 10:
            port_sample += f' ... (+{len(unique_ports)-10} more)'

        # Determine severity
        severity = self.get_severity_level(port_count)

        # Create finding data
        data = {
            'source_ip': src_ip,
            'scan_type': scan_type,
            'total_attempts': count,
            'unique_ports': port_count,
            'time_range': time_range,
            'duration_seconds': duration,
            'target_hosts': target_count,
            'targets': target_info,
            'ports_scanned': port_sample,
            'scan_rate': f"{port_count/max(duration/60, 1):.1f} ports/minute",
            'threshold': self.threshold
        }

        # Create recommendations
        recommendations = [
            f"Investigate source IP {src_ip} immediately",
            "Check firewall logs for blocked connections from this IP",
            "Review if any connections from this IP were successful",
            "Consider blocking the source IP if it's not legitimate",
            "Monitor for follow-up exploitation attempts"
        ]

        finding = self.format_finding(
            severity=severity,
            data=data,
            timestamp=valid_timestamps[-1].isoformat() if valid_timestamps else None,
            recommendations=recommendations,
            event_count=count
        )

        return finding

    def determine_scan_type(self, connections, unique_ports):
        """Determine the type of port scan based on patterns"""
        # Check for common service ports
        common_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 3306, 5432, 8080}
        scanned_common = len(common_ports.intersection(unique_ports))

        # Analyze scan characteristics
        port_count = len(unique_ports)
        total_attempts = len(connections)

        # Determine scan type
        if scanned_common >= 5:
            return "Common Service Scan"
        elif port_count > 1000:
            return "Comprehensive Port Scan"
        elif all(port < 1024 for port in unique_ports):
            return "Well-Known Ports Scan"
        elif port_count > 100:
            return "Broad Port Scan"
        elif any(port in {135, 139, 445} for port in unique_ports):
            return "Windows SMB Scan"
        elif any(port in {21, 22, 23, 80, 443} for port in unique_ports):
            return "Service Discovery Scan"
        elif total_attempts > port_count * 3:
            return "Intensive Port Scan"
        else:
            return "Reconnaissance Scan"