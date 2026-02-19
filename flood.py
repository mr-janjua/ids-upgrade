#!/usr/bin/env python3
"""
Flood Detection Module for Meowmin IDS

Detects various flooding attacks:
- SYN Floods
- UDP Floods  
- ICMP Floods (ping floods)
- DNS Floods
- ACK Floods

TODO: add HTTP flood detection later
HTTP Flood Detection Postpone, requre deep inspection of security protocols and state tracking.
"""

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Tuple, List, Optional
from scapy.all import IP, TCP, UDP, ICMP
import json


class FloodDetector:
    
    # thresholds - tweak these based on your network
    SYN_THRESHOLD = 100  
    UDP_THRESHOLD = 500  
    ICMP_THRESHOLD = 200 
    DNS_THRESHOLD = 300  
    ACK_THRESHOLD = 150  
    
    TIME_WINDOW = 5  # seconds
    MIN_PACKETS = 50  # avoid false positives
    
    DNS_PORTS = [53, 5353]
    ALERT_COOLDOWN = 30  # don't spam alerts
    
    def __init__(self):
        # track stat per source IP
        self.src_stats: Dict[str, Dict[str, deque]] = defaultdict(
            lambda: {
                'syn_timestamps': deque(maxlen=10000), # store timestamps for SYN packets nothing more then 10k to avoid memory issues
                'udp_timestamps': deque(maxlen=10000), # same goes for here
                'icmp_timestamps': deque(maxlen=10000), # and here
                'dns_timestamps': deque(maxlen=10000),
                'ack_timestamps': deque(maxlen=10000),
                'last_alert': {}  
            }
        )
        self.flood_alerts: List[Dict] = []
    
    def _should_alert(self, src_ip: str, alert_type: str) -> bool:
        """check if we should alert or if we're in cooldown"""
        last_alert_time = self.src_stats[src_ip]['last_alert'].get(alert_type)
        if last_alert_time is None:
            return True
        
        time_diff = (datetime.now() - last_alert_time).total_seconds()
        return time_diff > self.ALERT_COOLDOWN
    
    def _calculate_pps(self, timestamps: deque) -> float:
        """calc packets per second"""
        if len(timestamps) < 2:
            return 0.0
        
        oldest = timestamps[0]
        newest = timestamps[-1]
        time_span = (newest - oldest).total_seconds()
        
        if time_span == 0:
            return float(len(timestamps))
        
        return len(timestamps) / time_span
    
    def _prune_old_timestamps(self, timestamps: deque) -> None:
        """remove old timestamps outside our window"""
        cutoff_time = datetime.now() - timedelta(seconds=self.TIME_WINDOW)
        while timestamps and timestamps[0] < cutoff_time:
            timestamps.popleft()
    
    def detect_syn_flood(self, pkt, src_ip: str, dst_ip: str) -> Optional[Dict]:
        """
        SYN flood detection - half-open connections attack
        legit traffic: ~10-50 pps, attack: >100 pps
        """
        if not pkt.haslayer(TCP):
            return None
        
        tcp_flags = pkt[TCP].flags
        # check SYN flag (0x02)
        if not (tcp_flags & 0x02):
            return None
        
        self.src_stats[src_ip]['syn_timestamps'].append(datetime.now())
        self._prune_old_timestamps(self.src_stats[src_ip]['syn_timestamps'])
        
        pps = self._calculate_pps(self.src_stats[src_ip]['syn_timestamps'])
        pkt_count = len(self.src_stats[src_ip]['syn_timestamps'])
        
        if pps > self.SYN_THRESHOLD and pkt_count > self.MIN_PACKETS:
            if self._should_alert(src_ip, 'syn_flood'):
                self.src_stats[src_ip]['last_alert']['syn_flood'] = datetime.now()
                
                alert = {
                    'type': 'SYN_FLOOD',
                    'severity': 'HIGH',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'pps': round(pps, 2),
                    'packet_count': pkt_count,
                    'threshold': self.SYN_THRESHOLD,
                    'dport': pkt[TCP].dport,
                    'timestamp': datetime.now().isoformat()
                }
                self.flood_alerts.append(alert)
                return alert
        
        return None
    
    def detect_udp_flood(self, pkt, src_ip: str, dst_ip: str) -> Optional[Dict]:
        """UDP flood - high volume UDP packets"""
        if not pkt.haslayer(UDP):
            return None
        
        self.src_stats[src_ip]['udp_timestamps'].append(datetime.now())
        self._prune_old_timestamps(self.src_stats[src_ip]['udp_timestamps'])
        
        pps = self._calculate_pps(self.src_stats[src_ip]['udp_timestamps'])
        pkt_count = len(self.src_stats[src_ip]['udp_timestamps'])
        
        # detect flood
        if pps > self.UDP_THRESHOLD and pkt_count > self.MIN_PACKETS:
            if self._should_alert(src_ip, 'udp_flood'):
                self.src_stats[src_ip]['last_alert']['udp_flood'] = datetime.now()
                
                alert = {
                    'type': 'UDP_FLOOD',
                    'severity': 'HIGH',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'pps': round(pps, 2),
                    'packet_count': pkt_count,
                    'threshold': self.UDP_THRESHOLD,
                    'dport': pkt[UDP].dport,
                    'timestamp': datetime.now().isoformat()
                }
                self.flood_alerts.append(alert)
                return alert
        
        return None
    
    def detect_icmp_flood(self, pkt, src_ip: str, dst_ip: str) -> Optional[Dict]:
        """ping flood detection"""
        if not pkt.haslayer(ICMP):
            return None
        
        icmp_type = pkt[ICMP].type
        if icmp_type != 8:  # only echo requests
            return None
        
        self.src_stats[src_ip]['icmp_timestamps'].append(datetime.now())
        self._prune_old_timestamps(self.src_stats[src_ip]['icmp_timestamps'])
        
        pps = self._calculate_pps(self.src_stats[src_ip]['icmp_timestamps'])
        pkt_count = len(self.src_stats[src_ip]['icmp_timestamps'])
        
        if pps > self.ICMP_THRESHOLD and pkt_count > self.MIN_PACKETS:
            if self._should_alert(src_ip, 'icmp_flood'):
                self.src_stats[src_ip]['last_alert']['icmp_flood'] = datetime.now()
                
                alert = {
                    'type': 'ICMP_FLOOD',
                    'severity': 'HIGH',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'pps': round(pps, 2),
                    'packet_count': pkt_count,
                    'threshold': self.ICMP_THRESHOLD,
                    'icmp_type': icmp_type,
                    'timestamp': datetime.now().isoformat()
                }
                self.flood_alerts.append(alert)
                return alert
        
        return None
    
    def detect_dns_flood(self, pkt, src_ip: str, dst_ip: str) -> Optional[Dict]:
        """DNS query flood detection"""
        if not pkt.haslayer(UDP):
            return None
        
        dport = pkt[UDP].dport
        if dport not in self.DNS_PORTS:
            return None
        
        self.src_stats[src_ip]['dns_timestamps'].append(datetime.now())
        self._prune_old_timestamps(self.src_stats[src_ip]['dns_timestamps'])
        
        pps = self._calculate_pps(self.src_stats[src_ip]['dns_timestamps'])
        pkt_count = len(self.src_stats[src_ip]['dns_timestamps'])
        
        if pps > self.DNS_THRESHOLD and pkt_count > self.MIN_PACKETS:
            if self._should_alert(src_ip, 'dns_flood'):
                self.src_stats[src_ip]['last_alert']['dns_flood'] = datetime.now()
                
                alert = {
                    'type': 'DNS_FLOOD',
                    'severity': 'MEDIUM',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'pps': round(pps, 2),
                    'packet_count': pkt_count,
                    'threshold': self.DNS_THRESHOLD,
                    'dport': dport,
                    'timestamp': datetime.now().isoformat()
                }
                self.flood_alerts.append(alert)
                return alert
        
        return None
    
    def detect_ack_flood(self, pkt, src_ip: str, dst_ip: str) -> Optional[Dict]:
        """ACK flood - excessive TCP ACK packets"""
        if not pkt.haslayer(TCP):
            return None
        
        tcp_flags = pkt[TCP].flags
        # ACK flag set, but not SYN or FIN
        if not (tcp_flags & 0x10) or (tcp_flags & 0x02) or (tcp_flags & 0x01):
            return None
        
        self.src_stats[src_ip]['ack_timestamps'].append(datetime.now())
        self._prune_old_timestamps(self.src_stats[src_ip]['ack_timestamps'])
        
        pps = self._calculate_pps(self.src_stats[src_ip]['ack_timestamps'])
        pkt_count = len(self.src_stats[src_ip]['ack_timestamps'])
        
        if pps > self.ACK_THRESHOLD and pkt_count > self.MIN_PACKETS:
            if self._should_alert(src_ip, 'ack_flood'):
                self.src_stats[src_ip]['last_alert']['ack_flood'] = datetime.now()
                
                alert = {
                    'type': 'ACK_FLOOD',
                    'severity': 'MEDIUM',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'pps': round(pps, 2),
                    'packet_count': pkt_count,
                    'threshold': self.ACK_THRESHOLD,
                    'dport': pkt[TCP].dport,
                    'timestamp': datetime.now().isoformat()
                }
                self.flood_alerts.append(alert)
                return alert
        
        return None
    
    def check_packet(self, pkt) -> Optional[Dict]:
        """main packet analysis - checks all flood types"""
        if not pkt.haslayer(IP):
            return None
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # check each type
        alert = (
            self.detect_syn_flood(pkt, src_ip, dst_ip) or
            self.detect_udp_flood(pkt, src_ip, dst_ip) or
            self.detect_icmp_flood(pkt, src_ip, dst_ip) or
            self.detect_dns_flood(pkt, src_ip, dst_ip) or
            self.detect_ack_flood(pkt, src_ip, dst_ip)
        )
        
        return alert
    
    def get_source_stats(self, src_ip: str) -> Dict:
        """get traffic stats for an IP"""
        stats = self.src_stats[src_ip]
        return {
            'syn_packets': len(stats['syn_timestamps']),
            'syn_pps': round(self._calculate_pps(stats['syn_timestamps']), 2),
            'udp_packets': len(stats['udp_timestamps']),
            'udp_pps': round(self._calculate_pps(stats['udp_timestamps']), 2),
            'icmp_packets': len(stats['icmp_timestamps']),
            'icmp_pps': round(self._calculate_pps(stats['icmp_timestamps']), 2),
            'dns_packets': len(stats['dns_timestamps']),
            'dns_pps': round(self._calculate_pps(stats['dns_timestamps']), 2),
            'ack_packets': len(stats['ack_timestamps']),
            'ack_pps': round(self._calculate_pps(stats['ack_timestamps']), 2),
        }
    
    def reset_stats(self, src_ip: Optional[str] = None) -> None:
        """reset stats for one IP or all"""
        if src_ip:
            if src_ip in self.src_stats:
                del self.src_stats[src_ip]
        else:
            self.src_stats.clear()