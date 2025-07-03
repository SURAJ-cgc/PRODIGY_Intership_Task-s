#!/usr/bin/env python3
"""
Network Packet Analyzer Tool
Educational packet capture and analysis tool

IMPORTANT: This tool is for educational purposes only.
Use only on networks you own or have explicit permission to monitor.
Unauthorized packet capture may violate laws and regulations.
"""

import socket
import struct
import textwrap
import sys
import argparse
from datetime import datetime
import json

class PacketAnalyzer:
    def __init__(self, interface=None, count=10):
        self.interface = interface
        self.packet_count = count
        self.captured_packets = []
        
    def create_socket(self):
        """Create a raw socket for packet capture"""
        try:
            # Create raw socket
            if sys.platform.startswith('win'):
                # Windows
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                # Linux/Unix
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            
            return sock
        except PermissionError:
            print("❌ Error: Root/Administrator privileges required for packet capture")
            print("Please run with sudo (Linux/Mac) or as Administrator (Windows)")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error creating socket: {e}")
            sys.exit(1)

    def parse_ethernet_header(self, data):
        """Parse Ethernet header"""
        eth_header = struct.unpack('!6s6sH', data[:14])
        dest_mac = ':'.join(['%02x' % b for b in eth_header[0]])
        src_mac = ':'.join(['%02x' % b for b in eth_header[1]])
        eth_type = socket.ntohs(eth_header[2])
        
        return {
            'dest_mac': dest_mac,
            'src_mac': src_mac,
            'type': eth_type
        }

    def parse_ip_header(self, data):
        """Parse IP header"""
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
        
        version = ip_header[0] >> 4
        ihl = ip_header[0] & 0xF
        ttl = ip_header[5]
        protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])
        
        return {
            'version': version,
            'header_length': ihl * 4,
            'ttl': ttl,
            'protocol': protocol,
            'src_ip': src_ip,
            'dest_ip': dest_ip
        }

    def parse_tcp_header(self, data):
        """Parse TCP header"""
        tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
        
        src_port = tcp_header[0]
        dest_port = tcp_header[1]
        seq_num = tcp_header[2]
        ack_num = tcp_header[3]
        flags = tcp_header[5]
        
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'sequence': seq_num,
            'acknowledgment': ack_num,
            'flags': flags
        }

    def parse_udp_header(self, data):
        """Parse UDP header"""
        udp_header = struct.unpack('!HHHH', data[:8])
        
        return {
            'src_port': udp_header[0],
            'dest_port': udp_header[1],
            'length': udp_header[2],
            'checksum': udp_header[3]
        }

    def get_protocol_name(self, protocol_num):
        """Get protocol name from number"""
        protocols = {
            1: 'ICMP',
            2: 'IGMP',
            6: 'TCP',
            17: 'UDP',
            41: 'IPv6',
            89: 'OSPF'
        }
        return protocols.get(protocol_num, f'Unknown({protocol_num})')

    def format_payload(self, data, max_length=100):
        """Format payload data for display"""
        if len(data) == 0:
            return "No payload data"
        
        # Convert to hex representation
        hex_data = ' '.join(['%02x' % b for b in data[:max_length]])
        
        # Try to decode as ASCII (for readable text)
        try:
            ascii_data = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in data[:max_length]])
        except:
            ascii_data = "Binary data"
        
        return {
            'hex': hex_data,
            'ascii': ascii_data,
            'length': len(data)
        }

    def analyze_packet(self, packet_data):
        """Analyze a single packet"""
        packet_info = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'size': len(packet_data)
        }
        
        try:
            if sys.platform.startswith('win'):
                # Windows - start with IP header
                ip_info = self.parse_ip_header(packet_data)
                packet_info['ip'] = ip_info
                payload_offset = ip_info['header_length']
            else:
                # Linux - start with Ethernet header
                eth_info = self.parse_ethernet_header(packet_data)
                packet_info['ethernet'] = eth_info
                
                if eth_info['type'] == 0x0800:  # IPv4
                    ip_info = self.parse_ip_header(packet_data[14:])
                    packet_info['ip'] = ip_info
                    payload_offset = 14 + ip_info['header_length']
                else:
                    return packet_info
            
            # Parse transport layer
            if ip_info['protocol'] == 6:  # TCP
                tcp_info = self.parse_tcp_header(packet_data[payload_offset:])
                packet_info['tcp'] = tcp_info
                payload_offset += 20
            elif ip_info['protocol'] == 17:  # UDP
                udp_info = self.parse_udp_header(packet_data[payload_offset:])
                packet_info['udp'] = udp_info
                payload_offset += 8
            
            # Extract payload
            payload_data = packet_data[payload_offset:]
            if payload_data:
                packet_info['payload'] = self.format_payload(payload_data)
            
            packet_info['protocol_name'] = self.get_protocol_name(ip_info['protocol'])
            
        except Exception as e:
            packet_info['error'] = f"Parsing error: {e}"
        
        return packet_info

    def display_packet(self, packet_info, packet_num):
        """Display packet information in a formatted way"""
        print(f"\n{'='*60}")
        print(f"📦 PACKET #{packet_num}")
        print(f"{'='*60}")
        print(f"🕒 Timestamp: {packet_info['timestamp']}")
        print(f"📏 Size: {packet_info['size']} bytes")
        
        if 'ethernet' in packet_info:
            eth = packet_info['ethernet']
            print(f"\n🔗 ETHERNET HEADER:")
            print(f"   Source MAC: {eth['src_mac']}")
            print(f"   Dest MAC: {eth['dest_mac']}")
            print(f"   Type: 0x{eth['type']:04x}")
        
        if 'ip' in packet_info:
            ip = packet_info['ip']
            print(f"\n🌐 IP HEADER:")
            print(f"   Version: IPv{ip['version']}")
            print(f"   Source IP: {ip['src_ip']}")
            print(f"   Destination IP: {ip['dest_ip']}")
            print(f"   Protocol: {packet_info.get('protocol_name', 'Unknown')}")
            print(f"   TTL: {ip['ttl']}")
        
        if 'tcp' in packet_info:
            tcp = packet_info['tcp']
            print(f"\n🚢 TCP HEADER:")
            print(f"   Source Port: {tcp['src_port']}")
            print(f"   Destination Port: {tcp['dest_port']}")
            print(f"   Sequence: {tcp['sequence']}")
            print(f"   Acknowledgment: {tcp['acknowledgment']}")
            print(f"   Flags: 0x{tcp['flags']:02x}")
        
        if 'udp' in packet_info:
            udp = packet_info['udp']
            print(f"\n📡 UDP HEADER:")
            print(f"   Source Port: {udp['src_port']}")
            print(f"   Destination Port: {udp['dest_port']}")
            print(f"   Length: {udp['length']}")
        
        if 'payload' in packet_info:
            payload = packet_info['payload']
            print(f"\n📄 PAYLOAD DATA ({payload['length']} bytes):")
            print(f"   Hex: {payload['hex'][:50]}{'...' if len(payload['hex']) > 50 else ''}")
            print(f"   ASCII: {payload['ascii'][:50]}{'...' if len(payload['ascii']) > 50 else ''}")
        
        if 'error' in packet_info:
            print(f"\n❌ ERROR: {packet_info['error']}")

    def capture_packets(self):
        """Main packet capture loop"""
        print("🔍 Network Packet Analyzer")
        print("=" * 40)
        print("⚠️  EDUCATIONAL USE ONLY")
        print("📚 Use only on networks you own or have permission to monitor")
        print("=" * 40)
        print(f"📡 Capturing {self.packet_count} packets...\n")
        
        sock = self.create_socket()
        
        try:
            for i in range(self.packet_count):
                packet_data, addr = sock.recvfrom(65536)
                packet_info = self.analyze_packet(packet_data)
                self.captured_packets.append(packet_info)
                self.display_packet(packet_info, i + 1)
                
        except KeyboardInterrupt:
            print("\n\n⏹️  Capture interrupted by user")
        except Exception as e:
            print(f"\n❌ Error during capture: {e}")
        finally:
            if sys.platform.startswith('win'):
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()
        
        print(f"\n✅ Capture complete. {len(self.captured_packets)} packets captured.")

    def save_to_file(self, filename):
        """Save captured packets to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.captured_packets, f, indent=2)
            print(f"💾 Packets saved to {filename}")
        except Exception as e:
            print(f"❌ Error saving file: {e}")

    def display_summary(self):
        """Display capture summary"""
        if not self.captured_packets:
            return
        
        protocols = {}
        total_size = 0
        
        for packet in self.captured_packets:
            protocol = packet.get('protocol_name', 'Unknown')
            protocols[protocol] = protocols.get(protocol, 0) + 1
            total_size += packet['size']
        
        print(f"\n📊 CAPTURE SUMMARY")
        print("=" * 30)
        print(f"Total packets: {len(self.captured_packets)}")
        print(f"Total size: {total_size} bytes")
        print(f"Average size: {total_size // len(self.captured_packets)} bytes")
        print("\nProtocol distribution:")
        for protocol, count in protocols.items():
            percentage = (count / len(self.captured_packets)) * 100
            print(f"  {protocol}: {count} packets ({percentage:.1f}%)")

def main():
    parser = argparse.ArgumentParser(description='Network Packet Analyzer - Educational Tool')
    parser.add_argument('-c', '--count', type=int, default=10,
                      help='Number of packets to capture (default: 10)')
    parser.add_argument('-o', '--output', type=str,
                      help='Output file to save captured packets (JSON format)')
    parser.add_argument('-s', '--summary', action='store_true',
                      help='Display capture summary')
    
    args = parser.parse_args()
    
    # Ethical use warning
    print("\n" + "="*60)
    print("⚠️  IMPORTANT ETHICAL NOTICE")
    print("="*60)
    print("This tool is for EDUCATIONAL PURPOSES ONLY")
    print("• Only use on networks you own or have explicit permission to monitor")
    print("• Unauthorized packet capture may violate laws and regulations")
    print("• Be responsible and respect privacy")
    print("="*60)
    
    response = input("\nDo you acknowledge and agree to use this tool ethically? (yes/no): ")
    if response.lower() not in ['yes', 'y']:
        print("Exiting. Tool usage not acknowledged.")
        sys.exit(0)
    
    analyzer = PacketAnalyzer(count=args.count)
    analyzer.capture_packets()
    
    if args.summary:
        analyzer.display_summary()
    
    if args.output:
        analyzer.save_to_file(args.output)

if __name__ == "__main__":
    main()
