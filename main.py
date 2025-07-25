#!/usr/bin/env python3

import socket
import struct
import sys
import threading
import time
from collections import defaultdict
import argparse

class PacketSniffer:
    def __init__(self, interface=None, filter_ports=None, capture_count=0):
        self.interface = interface
        self.filter_ports = filter_ports or []
        self.capture_count = capture_count
        self.packet_count = 0
        self.running = False
        self.stats = {
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'port_activity': defaultdict(int),
            'mac_addresses': set()
        }
        
    def create_socket(self):
        try:
            if sys.platform.startswith('win'):
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                if self.interface:
                    self.sock.bind((self.interface, 0))
                    
        except PermissionError:
            print("Error: Root/Administrator privileges required for raw socket access")
            sys.exit(1)
        except Exception as e:
            print(f"Error creating socket: {e}")
            sys.exit(1)
            
    def parse_ethernet_header(self, packet):
        if len(packet) < 14:
            return None, None, None
            
        eth_header = struct.unpack('!6s6sH', packet[:14])
        dest_mac = ':'.join(f'{b:02x}' for b in eth_header[0])
        src_mac = ':'.join(f'{b:02x}' for b in eth_header[1])
        eth_protocol = eth_header[2]
        
        self.stats['mac_addresses'].add(src_mac)
        self.stats['mac_addresses'].add(dest_mac)
        
        return dest_mac, src_mac, eth_protocol
        
    def parse_ip_header(self, packet, offset=0):
        if len(packet) < offset + 20:
            return None
            
        ip_header = struct.unpack('!BBHHHBBH4s4s', packet[offset:offset+20])
        
        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        header_length = ihl * 4
        
        if version != 4:
            return None
            
        protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])
        
        return {
            'version': version,
            'header_length': header_length,
            'protocol': protocol,
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'packet_length': len(packet)
        }
        
    def parse_tcp_header(self, packet, ip_header_length, offset=0):
        tcp_offset = offset + ip_header_length
        if len(packet) < tcp_offset + 20:
            return None
            
        tcp_header = struct.unpack('!HHLLBBHHH', packet[tcp_offset:tcp_offset+20])
        
        src_port = tcp_header[0]
        dest_port = tcp_header[1]
        sequence = tcp_header[2]
        acknowledgment = tcp_header[3]
        doff_reserved = tcp_header[4]
        tcp_header_length = (doff_reserved >> 4) * 4
        flags = tcp_header[5]
        
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        
        self.stats['port_activity'][src_port] += 1
        self.stats['port_activity'][dest_port] += 1
        
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'sequence': sequence,
            'acknowledgment': acknowledgment,
            'header_length': tcp_header_length,
            'flags': flag_names
        }
        
    def parse_udp_header(self, packet, ip_header_length, offset=0):
        udp_offset = offset + ip_header_length
        if len(packet) < udp_offset + 8:
            return None
            
        udp_header = struct.unpack('!HHHH', packet[udp_offset:udp_offset+8])
        
        src_port = udp_header[0]
        dest_port = udp_header[1]
        length = udp_header[2]
        checksum = udp_header[3]
        
        self.stats['port_activity'][src_port] += 1
        self.stats['port_activity'][dest_port] += 1
        
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'length': length,
            'checksum': checksum
        }
        
    def process_packet(self, packet):
        self.packet_count += 1
        
        if sys.platform.startswith('win'):
            eth_offset = 0
            dest_mac = src_mac = "N/A (Windows raw IP socket)"
        else:
            dest_mac, src_mac, eth_protocol = self.parse_ethernet_header(packet)
            if eth_protocol != 0x0800:
                return
            eth_offset = 14
            
        ip_info = self.parse_ip_header(packet, eth_offset)
        if not ip_info:
            return
            
        protocol_name = "Unknown"
        port_info = None
        
        if ip_info['protocol'] == 6:
            protocol_name = "TCP"
            port_info = self.parse_tcp_header(packet, ip_info['header_length'], eth_offset)
            self.stats['tcp_packets'] += 1
            
        elif ip_info['protocol'] == 17:
            protocol_name = "UDP"
            port_info = self.parse_udp_header(packet, ip_info['header_length'], eth_offset)
            self.stats['udp_packets'] += 1
            
        elif ip_info['protocol'] == 1:
            protocol_name = "ICMP"
            self.stats['icmp_packets'] += 1
            
        else:
            self.stats['other_packets'] += 1
            
        if self.filter_ports and port_info:
            if not (port_info['src_port'] in self.filter_ports or 
                   port_info['dest_port'] in self.filter_ports):
                return
                
        self.display_packet_info(self.packet_count, src_mac, dest_mac, 
                               ip_info, protocol_name, port_info)
                               
    def display_packet_info(self, count, src_mac, dest_mac, ip_info, protocol, port_info):
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        
        print(f"\n[{count:04d}] {timestamp} - {protocol} Packet")
        print(f"  MAC: {src_mac} -> {dest_mac}")
        print(f"  IP:  {ip_info['src_ip']} -> {ip_info['dest_ip']}")
        
        if port_info:
            if protocol == "TCP":
                flags_str = ','.join(port_info['flags']) if port_info['flags'] else 'None'
                print(f"  TCP: {port_info['src_port']} -> {port_info['dest_port']} "
                      f"[{flags_str}] Seq:{port_info['sequence']} Ack:{port_info['acknowledgment']}")
            elif protocol == "UDP":
                print(f"  UDP: {port_info['src_port']} -> {port_info['dest_port']} "
                      f"Len:{port_info['length']}")
                      
        print(f"  Size: {ip_info['packet_length']} bytes")
        
    def display_statistics(self):
        print("\n" + "="*60)
        print("CAPTURE STATISTICS")
        print("="*60)
        print(f"Total packets captured: {self.packet_count}")
        print(f"TCP packets: {self.stats['tcp_packets']}")
        print(f"UDP packets: {self.stats['udp_packets']}")
        print(f"ICMP packets: {self.stats['icmp_packets']}")
        print(f"Other packets: {self.stats['other_packets']}")
        
        if self.stats['mac_addresses']:
            print(f"\nUnique MAC addresses seen: {len(self.stats['mac_addresses'])}")
            for mac in sorted(self.stats['mac_addresses']):
                if mac != "N/A (Windows raw IP socket)":
                    print(f"  {mac}")
                    
        if self.stats['port_activity']:
            print("\nTop 10 most active ports:")
            sorted_ports = sorted(self.stats['port_activity'].items(), 
                                key=lambda x: x[1], reverse=True)[:10]
            for port, count in sorted_ports:
                service = self.get_port_service(port)
                print(f"  Port {port:5d}: {count:4d} packets {service}")
                
    def get_port_service(self, port):
        common_ports = {
            20: "(FTP-DATA)", 21: "(FTP)", 22: "(SSH)", 23: "(TELNET)",
            25: "(SMTP)", 53: "(DNS)", 80: "(HTTP)", 110: "(POP3)",
            143: "(IMAP)", 443: "(HTTPS)", 993: "(IMAPS)", 995: "(POP3S)",
            3389: "(RDP)", 5432: "(PostgreSQL)", 3306: "(MySQL)"
        }
        return common_ports.get(port, "")
        
    def start_capture(self):
        print("Starting packet capture...")
        print("Press Ctrl+C to stop")
        
        if self.filter_ports:
            print(f"Filtering for ports: {', '.join(map(str, self.filter_ports))}")
            
        self.create_socket()
        self.running = True
        
        try:
            while self.running:
                packet, addr = self.sock.recvfrom(65565)
                self.process_packet(packet)
                
                if self.capture_count > 0 and self.packet_count >= self.capture_count:
                    break
                    
        except KeyboardInterrupt:
            print("\nCapture interrupted by user")
        except Exception as e:
            print(f"Error during capture: {e}")
        finally:
            self.cleanup()
            
    def cleanup(self):
        if hasattr(self, 'sock'):
            if sys.platform.startswith('win'):
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self.sock.close()
        self.running = False
        self.display_statistics()

def main():
    parser = argparse.ArgumentParser(description="Network Port and MAC Address Sniffer")
    parser.add_argument('-i', '--interface', help='Network interface to capture on (Linux only)')
    parser.add_argument('-p', '--ports', nargs='+', type=int, 
                       help='Filter specific ports (e.g., -p 80 443 22)')
    parser.add_argument('-c', '--count', type=int, default=0,
                       help='Number of packets to capture (0 = unlimited)')
    
    args = parser.parse_args()
    
    if sys.platform not in ['linux', 'linux2', 'win32']:
        print("Warning: This sniffer is optimized for Linux and Windows")
        
    try:
        sniffer = PacketSniffer(
            interface=args.interface,
            filter_ports=args.ports,
            capture_count=args.count
        )
        sniffer.start_capture()
        
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
