"""
SALAT v2 - JSON Log Parser
Parse JSON log files with support for arrays and newline-delimited JSON
"""

import json
from lib.parser import normalize_event


def parse_json(filename):
    """
    Parse JSON log file

    Args:
        filename: Path to JSON file

    Returns:
        List of normalized events
    """
    events = []

    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read().strip()

            if not content:
                return []

            # Try to parse as complete JSON first
            try:
                data = json.loads(content)

                # Handle single object
                if isinstance(data, dict):
                    events = [data]
                # Handle array of objects
                elif isinstance(data, list):
                    events = data
                else:
                    raise ValueError("JSON must contain object or array of objects")

            except json.JSONDecodeError:
                # Try newline-delimited JSON
                events = parse_ndjson(content)

    except Exception as e:
        raise ValueError(f"Failed to parse JSON file: {e}")

    # Normalize all events
    normalized_events = []
    for event in events:
        if isinstance(event, dict):
            normalized = normalize_event(event, 'json')
            normalized_events.append(normalized)

    return normalized_events


def parse_ndjson(content):
    """Parse newline-delimited JSON"""
    events = []
    lines = content.split('\n')

    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue

        try:
            event = json.loads(line)
            if isinstance(event, dict):
                events.append(event)
        except json.JSONDecodeError as e:
            # Skip malformed lines but log warning
            print(f"Warning: Skipping malformed JSON on line {line_num}: {e}")
            continue

    return events


def is_valid_json_file(filename):
    """Check if file contains valid JSON"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            json.loads(content)
        return True
    except (json.JSONDecodeError, FileNotFoundError, IOError):
        return False