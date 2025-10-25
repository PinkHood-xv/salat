"""
SALAT v2 - Brute Force Detection
Detect brute force authentication attacks
"""

from collections import defaultdict
from .base import BaseDetector


class BruteForceDetector(BaseDetector):
    """Detect brute force authentication attacks"""

    def __init__(self, threshold=5, time_window=300, **kwargs):
        super().__init__(threshold, time_window, **kwargs)

    def get_detector_name(self):
        return "Brute Force Attack"

    def get_detector_description(self):
        return "Detects multiple failed authentication attempts from the same source"

    def detect(self, events):
        """
        Detect brute force patterns in events

        Args:
            events: List of normalized events

        Returns:
            List of findings
        """
        findings = []

        # Filter for authentication failure events
        auth_failures = self.filter_failed_auth_events(events)

        if not auth_failures:
            return findings

        # Group by source IP
        ip_groups = self.group_events_by_field(auth_failures, 'src_ip')

        # Analyze each IP's failed attempts
        for src_ip, failures in ip_groups.items():
            if len(failures) >= self.threshold:
                # Check if attempts are within time window
                if self.within_time_window(failures):
                    finding = self.create_brute_force_finding(src_ip, failures)
                    findings.append(finding)

        return findings

    def filter_failed_auth_events(self, events):
        """Filter events for authentication failures"""
        failed_auth_events = []

        # Failed authentication indicators
        failed_indicators = [
            'authentication_failure',
            'failed_login',
            'login_failed',
            'auth_failed',
            'ssh_failed_login',
            'invalid_credentials',
            'authentication_failure',
            'failed',
            'denied'
        ]

        # HTTP/Status code indicators
        http_fail_codes = ['401', '403']

        for event in events:
            is_failed_auth = False

            # Check event type
            event_type = str(event.get('event_type', '')).lower()
            if any(indicator in event_type for indicator in failed_indicators):
                is_failed_auth = True

            # Check message content
            if not is_failed_auth:
                message = str(event.get('message', '')).lower()
                if any(indicator in message for indicator in failed_indicators):
                    is_failed_auth = True

            # Check for HTTP status codes
            if not is_failed_auth:
                status = str(event.get('status', ''))
                if status in http_fail_codes:
                    is_failed_auth = True

            # Check raw data for other indicators
            if not is_failed_auth:
                raw_data = str(event.get('raw', {})).lower()
                if any(indicator in raw_data for indicator in failed_indicators):
                    is_failed_auth = True

            if is_failed_auth:
                failed_auth_events.append(event)

        return failed_auth_events

    def create_brute_force_finding(self, src_ip, failures):
        """Create brute force finding from failed attempts"""
        count = len(failures)

        # Get time range
        timestamps = [self.parse_timestamp(f.get('timestamp')) for f in failures]
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

        # Get target information
        targets = self.get_unique_values(failures, 'dst_ip')
        target_info = ', '.join(list(targets)[:3]) if targets else 'Unknown'
        if len(targets) > 3:
            target_info += f' (+{len(targets)-3} more)'

        # Get usernames if available
        usernames = self.get_unique_values(failures, 'username') or \
                   self.get_unique_values(failures, 'user')
        username_info = ', '.join(list(usernames)[:3]) if usernames else 'Unknown'

        # Determine severity
        severity = self.get_severity_level(count)

        # Create finding data
        data = {
            'source_ip': src_ip,
            'failed_attempts': count,
            'time_range': time_range,
            'duration_seconds': duration,
            'targets': target_info,
            'usernames': username_info,
            'threshold': self.threshold,
            'time_window': self.time_window,
            'attack_rate': f"{count/max(duration/60, 1):.1f} attempts/minute"
        }

        # Create recommendation
        recommendations = [
            f"Block source IP {src_ip} immediately",
            "Review logs for successful authentication attempts from this IP",
            "Check if this IP belongs to legitimate infrastructure",
            "Consider implementing rate limiting for authentication attempts",
            "Monitor for successful logins following this activity"
        ]

        finding = self.format_finding(
            severity=severity,
            data=data,
            timestamp=valid_timestamps[-1].isoformat() if valid_timestamps else None,
            recommendations=recommendations,
            event_count=count
        )

        return finding

    def get_default_threshold(self):
        """Default threshold for brute force detection"""
        return 5

    def get_default_time_window(self):
        """Default time window for brute force detection (5 minutes)"""
        return 300