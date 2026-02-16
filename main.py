#!/usr/bin/env python3
"""
Meowmin IDS - Basic Intrusion Detection System
"""

import json
from scapy.all import sniff, IP, TCP, UDP, Ether, get_if_list
from datetime import datetime
from pathlib import Path
from flood import FloodDetector

# Suspicious ports to monitor
SUS_PORTS = [
    22,    # SSH
    23,    # Telnet
    445,   # SMB
    137, 138, 139,  # NetBIOS
    1433,  # SQL Server
    3306,  # MySQL
    3389,  # RDP
    5900,  # VNC
    6379,  # Redis
    27017, # MongoDB
    9200,  # Elasticsearch
]

# Blacklist - IPs, MAC addresses
BLACKLIST_IPS = [
    '65.45.32.1',
    '192.168.1.100',
    '192.168.0.100',
    '10.0.0.50',
]

BLACKLIST_MAC = [
    '00:11:22:33:44:55',  # Add suspicious MACs here
    '66:77:88:99:AA:BB',
    'CC:DD:EE:FF:00:11',
]

Path('alerts').mkdir(exist_ok=True)

alert_count = 0
flood_detector = FloodDetector()


def handle_packet(pkt):
    """Analyze packet for suspicious activity: blacklist, sus ports, and flooding"""
    global alert_count
    
    # Get MAC addresses
    src_mac = pkt.src if hasattr(pkt, 'src') else None
    dst_mac = pkt.dst if hasattr(pkt, 'dst') else None
    
    # Skip if no IP
    if not pkt.haslayer(IP):
        return
    
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    
    # Check for flooding attacks first
    flood_alert = flood_detector.check_packet(pkt)
    if flood_alert:
        alert_count += 1
        reason = f"{flood_alert['type']}: {flood_alert['pps']} pps (threshold: {flood_alert['threshold']} pps)"
        msg = f"\033[91m[ALERT {alert_count}] {datetime.now().strftime('%H:%M:%S')} - {reason}\033[0m"
        print(msg, flush=True)
        
        # Save to file
        alert_data = {
            'time': datetime.now().isoformat(),
            'alert_type': 'FLOOD_DETECTION',
            'reason': reason,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_mac': src_mac,
            'dst_mac': dst_mac,
            'flood_details': flood_alert
        }
        with open(f'alerts/alerts_{datetime.now().strftime("%Y%m%d")}.json', 'a') as f:
            json.dump(alert_data, f)
            f.write('\n')
        return  # Don't check other detections if flood detected
    
    # Alert reason
    reason = None
    
    # Check blacklist - IPs
    if src_ip in BLACKLIST_IPS:
        reason = f"BLACKLIST SOURCE IP: {src_ip}"
    elif dst_ip in BLACKLIST_IPS:
        reason = f"BLACKLIST DEST IP: {dst_ip}"
    
    # Check blacklist - MAC
    elif src_mac in BLACKLIST_MAC:
        reason = f"BLACKLIST SOURCE MAC: {src_mac}"
    elif dst_mac in BLACKLIST_MAC:
        reason = f"BLACKLIST DEST MAC: {dst_mac}"
    
    # Check SUS ports
    elif pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if sport in SUS_PORTS:
            reason = f"SUS SOURCE PORT: {sport} from {src_ip}"
        elif dport in SUS_PORTS:
            reason = f"SUS DEST PORT: {dport} to {dst_ip}"
    
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        if sport in SUS_PORTS:
            reason = f"SUS SOURCE PORT: {sport} from {src_ip}"
        elif dport in SUS_PORTS:
            reason = f"SUS DEST PORT: {dport} to {dst_ip}"
    
    # If we found something SUS, alert
    if reason:
        alert_count += 1
        msg = f"\033[91m[ALERT {alert_count}] {datetime.now().strftime('%H:%M:%S')} - {reason}\033[0m"
        print(msg, flush=True)
        
        # Save to file
        with open(f'alerts/alerts_{datetime.now().strftime("%Y%m%d")}.json', 'a') as f:
            json.dump({
                'time': datetime.now().isoformat(),
                'alert_type': 'BLACKLIST_OR_SUSPICIOUS_PORT',
                'reason': reason,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_mac': src_mac,
                'dst_mac': dst_mac
            }, f)
            f.write('\n')


# Get interface
interface = None
for iface in get_if_list():
    if iface != 'lo':
        interface = iface
        break

print("\n" + "="*60)
print("Meowmin IDS - Running")
print(f"Your Network Interface: {interface}")
print(f"Suspicious Ports Are: {SUS_PORTS}")
print(f"Blacklist IPs Are: {BLACKLIST_IPS}")
print(f"Blacklist MACs Are: {BLACKLIST_MAC}")
print("\n[FLOOD DETECTION ENABLED]")
print(f"  SYN Flood Threshold: {flood_detector.SYN_THRESHOLD} pps")
print(f"  UDP Flood Threshold: {flood_detector.UDP_THRESHOLD} pps")
print(f"  ICMP Flood Threshold: {flood_detector.ICMP_THRESHOLD} pps")
print(f"  DNS Flood Threshold: {flood_detector.DNS_THRESHOLD} pps")
print(f"  ACK Flood Threshold: {flood_detector.ACK_THRESHOLD} pps")
print("="*60 + "\n")

try:
    sniff(iface=interface, prn=handle_packet, store=0)
except KeyboardInterrupt:
    print(f"\n[STOPPED] Total alerts: {alert_count}")
