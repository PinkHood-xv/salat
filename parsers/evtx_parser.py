"""
SALAT v2 - EVTX Parser
Parse Windows Event Log (EVTX) files
"""

from lib.parser import normalize_event


def parse_evtx(filename):
    """
    Parse EVTX file

    Args:
        filename: Path to EVTX file

    Returns:
        List of normalized events

    Note: This is a placeholder implementation.
    Full EVTX parsing requires additional dependencies like python-evtx
    """
    # Check for optional dependency
    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as e_views
        import xml.etree.ElementTree as ET
    except ImportError:
        raise ImportError(
            "EVTX parsing requires python-evtx. Install with: pip install python-evtx"
        )

    events = []

    try:
        with evtx.Evtx(filename) as log:
            for record in log.records():
                try:
                    # Parse XML content
                    xml_content = record.xml()
                    root = ET.fromstring(xml_content)

                    # Extract event data
                    event = extract_evtx_event_data(root)
                    if event:
                        normalized = normalize_event(event, 'evtx')
                        events.append(normalized)

                except Exception:
                    # Skip malformed records
                    continue

    except Exception as e:
        raise ValueError(f"Failed to parse EVTX file: {e}")

    return events


def extract_evtx_event_data(xml_root):
    """Extract event data from EVTX XML"""
    event = {}

    try:
        # Define namespace
        ns = {'': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        # Extract system information
        system = xml_root.find('.//System', ns)
        if system is not None:
            # Event ID
            event_id = system.find('.//EventID', ns)
            if event_id is not None:
                event['event_id'] = event_id.text

            # Timestamp
            time_created = system.find('.//TimeCreated', ns)
            if time_created is not None:
                event['timestamp'] = time_created.get('SystemTime')

            # Computer name
            computer = system.find('.//Computer', ns)
            if computer is not None:
                event['computer'] = computer.text

            # Channel
            channel = system.find('.//Channel', ns)
            if channel is not None:
                event['channel'] = channel.text

            # Level
            level = system.find('.//Level', ns)
            if level is not None:
                event['level'] = level.text

        # Extract event data
        event_data = xml_root.find('.//EventData', ns)
        if event_data is not None:
            for data in event_data.findall('.//Data', ns):
                name = data.get('Name')
                if name and data.text:
                    event[name.lower()] = data.text

        # Set event type based on channel and event ID
        event['event_type'] = determine_event_type(event)

        # Extract IP addresses if present
        extract_ip_addresses(event)

        return event

    except Exception:
        return None


def determine_event_type(event):
    """Determine event type from EVTX event data"""
    event_id = event.get('event_id', '')
    channel = event.get('channel', '').lower()

    # Security events
    if 'security' in channel:
        if event_id in ['4624', '4625']:
            return 'authentication'
        elif event_id in ['4648']:
            return 'explicit_logon'
        elif event_id in ['4634', '4647']:
            return 'logoff'
        elif event_id in ['4720', '4726']:
            return 'account_management'

    # System events
    elif 'system' in channel:
        if event_id in ['7001', '7002']:
            return 'service_control'
        elif event_id in ['6005', '6006']:
            return 'system_event'

    # Application events
    elif 'application' in channel:
        return 'application_event'

    return 'windows_event'


def extract_ip_addresses(event):
    """Extract IP addresses from EVTX event data"""
    # Look for common IP fields in event data
    ip_fields = ['ipaddress', 'sourceip', 'destinationip', 'clientip', 'serverip']

    for field_name, field_value in event.items():
        if any(ip_field in field_name.lower() for ip_field in ip_fields):
            # Basic IP validation
            if is_valid_ip(field_value):
                if 'source' in field_name.lower() or 'client' in field_name.lower():
                    event['src_ip'] = field_value
                elif 'destination' in field_name.lower() or 'server' in field_name.lower():
                    event['dst_ip'] = field_value


def is_valid_ip(ip_string):
    """Basic IP address validation"""
    try:
        import ipaddress
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False