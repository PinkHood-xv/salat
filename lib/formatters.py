"""
SALAT v2 - Format Dispatcher
Route output formatting to appropriate formatter
"""


def format_output(events, findings, args):
    """
    Format output based on requested format

    Args:
        events: List of filtered events
        findings: List of detection findings
        args: Parsed command-line arguments

    Returns:
        Formatted output string
    """
    format_type = args.output_format.lower()

    if format_type == 'json':
        from formatters.json_formatter import format_json
        return format_json(events, findings, args)

    elif format_type == 'html':
        from formatters.html import format_html
        return format_html(events, findings, args)

    elif format_type == 'csv':
        from formatters.csv_formatter import format_csv
        return format_csv(events, findings, args)

    else:  # text (default)
        from formatters.text import format_text
        return format_text(events, findings, args)


def get_supported_formats():
    """Get list of supported output formats"""
    return {
        'text': {
            'name': 'Plain Text',
            'description': 'Human-readable text output',
            'extension': '.txt'
        },
        'json': {
            'name': 'JSON',
            'description': 'Machine-readable JSON format',
            'extension': '.json'
        },
        'html': {
            'name': 'HTML Report',
            'description': 'Interactive HTML report',
            'extension': '.html'
        },
        'csv': {
            'name': 'CSV',
            'description': 'Comma-separated values for spreadsheets',
            'extension': '.csv'
        }
    }


def suggest_output_file(args):
    """Suggest output filename based on format"""
    if args.output:
        return args.output

    formats = get_supported_formats()
    extension = formats.get(args.output_format, {}).get('extension', '.txt')

    # Generate filename based on input
    import os
    from datetime import datetime

    base_name = os.path.splitext(os.path.basename(args.log_file))[0]
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    return f"salat_report_{base_name}_{timestamp}{extension}"