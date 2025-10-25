"""
SALAT v2 - PCAP Parser
Parse PCAP files using tshark for network traffic analysis
"""

import subprocess
import json
from lib.parser import normalize_event


def parse_pcap(filename):
    """
    Parse PCAP file using tshark

    Args:
        filename: Path to PCAP file

    Returns:
        List of normalized events
    """
    # Check if tshark is available
    if not check_tshark_available():
        raise RuntimeError("tshark is not installed. Please install Wireshark/tshark.")

    # Build tshark command for JSON output
    cmd = [
        'tshark',
        '-r', filename,
        '-T', 'json',
        '-e', 'frame.time_epoch',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'tcp.srcport',
        '-e', 'tcp.dstport',
        '-e', 'udp.srcport',
        '-e', 'udp.dstport',
        '-e', 'frame.protocols',
        '-e', 'frame.len'
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        if not result.stdout.strip():
            return []

        packets = json.loads(result.stdout)
        return parse_tshark_output(packets)

    except subprocess.CalledProcessError as e:
        raise ValueError(f"tshark error: {e.stderr}")
    except json.JSONDecodeError:
        raise ValueError("Failed to parse tshark JSON output")


def parse_tshark_output(packets):
    """Parse tshark JSON output into normalized events"""
    events = []

    for packet in packets:
        try:
            layers = packet.get('_source', {}).get('layers', {})

            # Extract basic packet info
            event = {
                'timestamp': None,
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'protocol': None,
                'length': None,
                'event_type': 'network_packet'
            }

            # Extract timestamp
            frame_time = layers.get('frame.time_epoch')
            if frame_time and isinstance(frame_time, list) and frame_time:
                try:
                    from datetime import datetime
                    timestamp = float(frame_time[0])
                    event['timestamp'] = datetime.fromtimestamp(timestamp).isoformat()
                except (ValueError, IndexError):
                    pass

            # Extract IP addresses
            ip_src = layers.get('ip.src')
            if ip_src and isinstance(ip_src, list) and ip_src:
                event['src_ip'] = ip_src[0]

            ip_dst = layers.get('ip.dst')
            if ip_dst and isinstance(ip_dst, list) and ip_dst:
                event['dst_ip'] = ip_dst[0]

            # Extract ports (TCP first, then UDP)
            tcp_src = layers.get('tcp.srcport')
            if tcp_src and isinstance(tcp_src, list) and tcp_src:
                event['src_port'] = int(tcp_src[0])
                event['protocol'] = 'TCP'

            tcp_dst = layers.get('tcp.dstport')
            if tcp_dst and isinstance(tcp_dst, list) and tcp_dst:
                event['dst_port'] = int(tcp_dst[0])
                if not event['protocol']:
                    event['protocol'] = 'TCP'

            # UDP ports (if no TCP)
            if not event['protocol']:
                udp_src = layers.get('udp.srcport')
                if udp_src and isinstance(udp_src, list) and udp_src:
                    event['src_port'] = int(udp_src[0])
                    event['protocol'] = 'UDP'

                udp_dst = layers.get('udp.dstport')
                if udp_dst and isinstance(udp_dst, list) and udp_dst:
                    event['dst_port'] = int(udp_dst[0])
                    if not event['protocol']:
                        event['protocol'] = 'UDP'

            # Extract protocol from frame.protocols
            protocols = layers.get('frame.protocols')
            if protocols and isinstance(protocols, list) and protocols:
                protocol_chain = protocols[0]
                if not event['protocol']:
                    # Extract highest level protocol
                    if 'tcp' in protocol_chain.lower():
                        event['protocol'] = 'TCP'
                    elif 'udp' in protocol_chain.lower():
                        event['protocol'] = 'UDP'
                    elif 'icmp' in protocol_chain.lower():
                        event['protocol'] = 'ICMP'

            # Extract frame length
            frame_len = layers.get('frame.len')
            if frame_len and isinstance(frame_len, list) and frame_len:
                try:
                    event['length'] = int(frame_len[0])
                except ValueError:
                    pass

            # Add raw packet data
            event['raw'] = packet

            # Normalize and add to events
            normalized = normalize_event(event, 'pcap')
            events.append(normalized)

        except Exception:
            # Skip malformed packets
            continue

    return events


def check_tshark_available():
    """Check if tshark is installed and available"""
    try:
        subprocess.run(['tshark', '--version'],
                      capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def get_pcap_summary(filename):
    """Get basic PCAP file statistics"""
    if not check_tshark_available():
        return None

    cmd = ['tshark', '-r', filename, '-q', '-z', 'conv,ip']

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError:
        return None