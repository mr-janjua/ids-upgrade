#!/usr/bin/env python3
"""
Test script for flood_detector.py
Simulates different flood attacks to verify detection works
"""

from scapy.all import IP, TCP, UDP, ICMP, Raw
from flood import FloodDetector
import time
import random

def test_syn_flood():
    """Test SYN flood detection"""
    print("\n[*] Testing SYN flood detection...")
    detector = FloodDetector()
    
    src_ip = "192.168.1.100"
    dst_ip = "10.0.0.1"
    
    # send normal traffic first (should NOT trigger)
    print("  - Sending 20 normal SYN packets...")
    for i in range(20):
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(dport=80, flags='S')
        result = detector.check_packet(pkt)
        time.sleep(0.1)  # 10 pps - normal
    
    if result:
        print("  [!] FALSE POSITIVE - normal traffic triggered alert")
    else:
        print("  [✓] Normal traffic passed")
    
    # now flood it
    print("  - Sending 200 SYN packets rapidly...")
    for i in range(200):
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(dport=80, flags='S', seq=i)
        result = detector.check_packet(pkt)
        if result:
            print(f"  [✓] SYN flood detected!")
            print(f"      PPS: {result['pps']}, Threshold: {result['threshold']}")
            print(f"      Packet count: {result['packet_count']}")
            break
    
    if not result:
        print("  [X] FAILED - flood not detected")
    
    return result is not None

def test_udp_flood():
    """Test UDP flood detection"""
    print("\n[*] Testing UDP flood detection...")
    detector = FloodDetector()
    
    src_ip = "192.168.1.101"
    dst_ip = "10.0.0.2"
    
    print("  - Sending 600 UDP packets rapidly...")
    result = None
    for i in range(600):
        pkt = IP(src=src_ip, dst=dst_ip)/UDP(dport=12345)/Raw(load="flood data")
        result = detector.check_packet(pkt)
        if result:
            print(f"  [✓] UDP flood detected!")
            print(f"      PPS: {result['pps']}, Threshold: {result['threshold']}")
            break
    
    if not result:
        print("  [X] FAILED - flood not detected")
    
    return result is not None

def test_icmp_flood():
    """Test ICMP flood (ping flood)"""
    print("\n[*] Testing ICMP flood detection...")
    detector = FloodDetector()
    
    src_ip = "192.168.1.102"
    dst_ip = "10.0.0.3"
    
    print("  - Sending 250 ICMP echo requests rapidly...")
    result = None
    for i in range(250):
        pkt = IP(src=src_ip, dst=dst_ip)/ICMP(type=8)  # echo request
        result = detector.check_packet(pkt)
        if result:
            print(f"  [✓] ICMP flood detected!")
            print(f"      PPS: {result['pps']}, Threshold: {result['threshold']}")
            break
    
    if not result:
        print("  [X] FAILED - flood not detected")
    
    return result is not None

def test_dns_flood():
    """Test DNS flood detection"""
    print("\n[*] Testing DNS flood detection...")
    detector = FloodDetector()
    
    src_ip = "192.168.1.103"
    dst_ip = "8.8.8.8"
    
    print("  - Sending 350 DNS queries rapidly...")
    result = None
    for i in range(350):
        pkt = IP(src=src_ip, dst=dst_ip)/UDP(dport=53)/Raw(load="dns query")
        result = detector.check_packet(pkt)
        if result:
            print(f"  [✓] DNS flood detected!")
            print(f"      PPS: {result['pps']}, Threshold: {result['threshold']}")
            break
    
    if not result:
        print("  [X] FAILED - flood not detected")
    
    return result is not None

def test_http_flood():
    """Test HTTP flood detection"""
    print("\n[*] Testing HTTP flood detection...")
    detector = FloodDetector()
    
    src_ip = "192.168.1.107"
    dst_ip = "10.0.0.8"
    
    print("  - Sending 400 HTTP GET requests rapidly...")
    result = None
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    for i in range(400):
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(dport=80, flags='PA')/Raw(load=payload)
        result = detector.check_packet(pkt)
        if result:
            print(f"  [✓] HTTP flood detected!")
            print(f"      PPS: {result['pps']}, Threshold: {result['threshold']}")
            break
    
    if not result:
        print("  [X] FAILED - flood not detected")
    
    return result is not None

def test_ack_flood():
    """Test ACK flood detection"""
    print("\n[*] Testing ACK flood detection...")
    detector = FloodDetector()
    
    src_ip = "192.168.1.104"
    dst_ip = "10.0.0.4"
    
    print("  - Sending 200 ACK packets rapidly...")
    result = None
    for i in range(200):
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(dport=443, flags='A', ack=1000)
        result = detector.check_packet(pkt)
        if result:
            print(f"  [✓] ACK flood detected!")
            print(f"      PPS: {result['pps']}, Threshold: {result['threshold']}")
            break
    
    if not result:
        print("  [X] FAILED - flood not detected")
    
    return result is not None

def test_alert_cooldown():
    """Test that alert cooldown works"""
    print("\n[*] Testing alert cooldown mechanism...")
    detector = FloodDetector()
    
    src_ip = "192.168.1.105"
    dst_ip = "10.0.0.5"
    
    # trigger first alert
    print("  - Triggering first SYN flood alert...")
    for i in range(150):
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(dport=80, flags='S')
        result = detector.check_packet(pkt)
        if result:
            print(f"  [✓] First alert triggered")
            break
    
    # try to trigger again immediately (should be blocked)
    print("  - Trying to trigger second alert immediately...")
    alert_count = 0
    for i in range(150):
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(dport=80, flags='S')
        result = detector.check_packet(pkt)
        if result:
            alert_count += 1
    
    if alert_count == 0:
        print(f"  [✓] Cooldown working - no spam alerts")
        return True
    else:
        print(f"  [!] WARNING - got {alert_count} additional alerts (cooldown may not be working)")
        return False

def test_stats():
    """Test statistics tracking"""
    print("\n[*] Testing statistics tracking...")
    detector = FloodDetector()
    
    src_ip = "192.168.1.106"
    dst_ip = "10.0.0.6"
    
    # send mixed traffic
    print("  - Sending mixed traffic (SYN, UDP, ICMP)...")
    for i in range(30):
        # SYN
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(dport=80, flags='S')
        detector.check_packet(pkt)
        
        # UDP
        pkt = IP(src=src_ip, dst=dst_ip)/UDP(dport=1234)
        detector.check_packet(pkt)
        
        # ICMP
        pkt = IP(src=src_ip, dst=dst_ip)/ICMP(type=8)
        detector.check_packet(pkt)
    
    stats = detector.get_source_stats(src_ip)
    print(f"  Stats for {src_ip}:")
    print(f"    SYN packets: {stats['syn_packets']}, PPS: {stats['syn_pps']}")
    print(f"    UDP packets: {stats['udp_packets']}, PPS: {stats['udp_pps']}")
    print(f"    ICMP packets: {stats['icmp_packets']}, PPS: {stats['icmp_pps']}")
    
    if stats['syn_packets'] == 30 and stats['udp_packets'] == 30 and stats['icmp_packets'] == 30:
        print("  [✓] Statistics tracking working correctly")
        return True
    else:
        print("  [X] FAILED - packet counts don't match")
        return False

def test_multi_source():
    """Test detection from multiple sources"""
    print("\n[*] Testing multi-source flood detection...")
    detector = FloodDetector()
    
    dst_ip = "10.0.0.7"
    
    print("  - Simulating SYN flood from 3 different sources...")
    sources = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
    detected = []
    
    for src in sources:
        for i in range(150):
            pkt = IP(src=src, dst=dst_ip)/TCP(dport=80, flags='S')
            result = detector.check_packet(pkt)
            if result and result['src_ip'] not in detected:
                detected.append(result['src_ip'])
                print(f"  [✓] Detected flood from {result['src_ip']}")
    
    if len(detected) == 3:
        print("  [✓] All 3 sources detected correctly")
        return True
    else:
        print(f"  [!] Only detected {len(detected)}/3 sources")
        return False

def run_all_tests():
    """Run all tests"""
    print("="*60)
    print("FLOOD DETECTOR TEST SUITE")
    print("="*60)
    
    results = {}
    results['SYN Flood'] = test_syn_flood()
    results['UDP Flood'] = test_udp_flood()
    results['ICMP Flood'] = test_icmp_flood()
    results['DNS Flood'] = test_dns_flood()
    results['HTTP Flood'] = test_http_flood()
    results['ACK Flood'] = test_ack_flood()
    results['Alert Cooldown'] = test_alert_cooldown()
    results['Statistics'] = test_stats()
    results['Multi-Source'] = test_multi_source()
    
    print("\n" + "="*60)
    print("TEST RESULTS SUMMARY")
    print("="*60)
    
    passed = 0
    for test_name, result in results.items():
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} {test_name}")
        if result:
            passed += 1
    
    print(f"\nTotal: {passed}/{len(results)} tests passed")
    print("="*60)

if __name__ == "__main__":
    run_all_tests()