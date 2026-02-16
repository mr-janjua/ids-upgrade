#!/usr/bin/env python3
"""
Example usage of FloodDetector
Shows how to integrate with real packet capture
"""

from scapy.all import sniff, IP
from flood import FloodDetector
import sys

def packet_handler(pkt):
    """Handle each captured packet"""
    alert = detector.check_packet(pkt)
    
    if alert:
        print(f"\n{'='*60}")
        print(f"🚨 ALERT: {alert['type']} detected!")
        print(f"{'='*60}")
        print(f"Source IP: {alert['src_ip']}")
        print(f"Destination IP: {alert['dst_ip']}")
        print(f"Packets/sec: {alert['pps']} (threshold: {alert['threshold']})")
        print(f"Total packets: {alert['packet_count']}")
        print(f"Severity: {alert['severity']}")
        print(f"Time: {alert['timestamp']}")
        print(f"{'='*60}\n")

def main():
    print("Starting Meowmin IDS - Flood Detector")
    print("Monitoring network traffic...")
    print("Press Ctrl+C to stop\n")
    
    try:
        # capture packets on all interfaces
        # you can specify interface like: iface="eth0"
        sniff(prn=packet_handler, store=False)
    except KeyboardInterrupt:
        print("\n\nStopping...")
        print_summary()
    except Exception as e:
        print(f"\nError: {e}")
        print("Note: You may need to run this with sudo/admin privileges")

def print_summary():
    """Print summary of detected attacks"""
    if detector.flood_alerts:
        print(f"\n{'='*60}")
        print(f"SESSION SUMMARY - {len(detector.flood_alerts)} alerts detected")
        print(f"{'='*60}")
        
        attack_types = {}
        for alert in detector.flood_alerts:
            attack_type = alert['type']
            if attack_type not in attack_types:
                attack_types[attack_type] = 0
            attack_types[attack_type] += 1
        
        for attack, count in attack_types.items():
            print(f"{attack}: {count} alerts")
        print(f"{'='*60}\n")
    else:
        print("\nNo flood attacks detected during this session.")

if __name__ == "__main__":
    detector = FloodDetector()
    main()