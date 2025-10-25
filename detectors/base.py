"""
SALAT v2 - Base Detector Class
Base class for all detection modules
"""

from abc import ABC, abstractmethod
from datetime import datetime


class BaseDetector(ABC):
    """Base class for all detection modules"""

    def __init__(self, threshold=None, time_window=None, **kwargs):
        """
        Initialize detector

        Args:
            threshold: Detection threshold (module-specific)
            time_window: Time window in seconds for detection
            **kwargs: Additional detector-specific parameters
        """
        self.threshold = threshold or self.get_default_threshold()
        self.time_window = time_window or self.get_default_time_window()
        self.name = self.get_detector_name()
        self.description = self.get_detector_description()
        self.kwargs = kwargs

    @abstractmethod
    def detect(self, events):
        """
        Run detection on events

        Args:
            events: List of normalized events

        Returns:
            List of findings (dicts with keys: severity, type, data, timestamp, etc.)
        """
        pass

    @abstractmethod
    def get_detector_name(self):
        """Return detector name"""
        pass

    @abstractmethod
    def get_detector_description(self):
        """Return detector description"""
        pass

    def get_default_threshold(self):
        """Return default threshold for this detector"""
        return 5

    def get_default_time_window(self):
        """Return default time window in seconds"""
        return 300

    def format_finding(self, severity, data, timestamp=None, **kwargs):
        """
        Format a finding for output

        Args:
            severity: Severity level (low, medium, high, critical)
            data: Finding-specific data dict
            timestamp: When the finding occurred
            **kwargs: Additional finding data

        Returns:
            Dict representing the finding
        """
        finding = {
            'detector': self.name,
            'severity': severity,
            'timestamp': timestamp or datetime.now().isoformat(),
            'data': data,
            'description': self.description
        }

        # Add any additional kwargs
        finding.update(kwargs)

        return finding

    def parse_timestamp(self, timestamp_str):
        """Parse timestamp from event"""
        if not timestamp_str:
            return None

        formats = [
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%b %d %H:%M:%S',
            '%Y-%m-%d'
        ]

        # Clean timestamp
        clean_timestamp = str(timestamp_str).split('+')[0].split('Z')[0]

        for fmt in formats:
            try:
                return datetime.strptime(clean_timestamp.split('.')[0], fmt)
            except ValueError:
                continue

        return None

    def within_time_window(self, events):
        """Check if events fall within configured time window"""
        if len(events) < 2:
            return True

        timestamps = []
        for event in events:
            ts = self.parse_timestamp(event.get('timestamp'))
            if ts:
                timestamps.append(ts)

        if len(timestamps) < 2:
            return True

        timestamps.sort()
        time_diff = (timestamps[-1] - timestamps[0]).total_seconds()
        return time_diff <= self.time_window

    def get_severity_level(self, count, threshold_multiplier=1.0):
        """
        Determine severity level based on count and threshold

        Args:
            count: Number of events/attempts
            threshold_multiplier: Multiplier for threshold levels

        Returns:
            Severity string: low, medium, high, critical
        """
        base_threshold = self.threshold * threshold_multiplier

        if count >= base_threshold * 4:
            return 'critical'
        elif count >= base_threshold * 2:
            return 'high'
        elif count >= base_threshold:
            return 'medium'
        else:
            return 'low'

    def filter_events_by_type(self, events, event_types):
        """Filter events by event type"""
        if isinstance(event_types, str):
            event_types = [event_types]

        filtered = []
        for event in events:
            event_type = event.get('event_type', '').lower()
            if any(etype.lower() in event_type for etype in event_types):
                filtered.append(event)

        return filtered

    def group_events_by_field(self, events, field):
        """Group events by a specific field value"""
        groups = {}

        for event in events:
            field_value = event.get(field)
            if field_value:
                if field_value not in groups:
                    groups[field_value] = []
                groups[field_value].append(event)

        return groups

    def get_unique_values(self, events, field):
        """Get unique values for a field across events"""
        values = set()

        for event in events:
            value = event.get(field)
            if value:
                values.add(value)

        return values