🔍 Key Features:
Packet Capture & Analysis:

Captures network packets using raw sockets
Parses Ethernet, IP, TCP, and UDP headers
Extracts and displays payload data in both hex and ASCII formats
Cross-platform support (Windows, Linux, macOS)

Information Display:

Source and destination IP addresses
MAC addresses (on Linux/Unix systems)
Protocol types (TCP, UDP, ICMP, etc.)
Port numbers for TCP/UDP
Packet timestamps and sizes
Payload data preview

Additional Features:

Configurable packet count
JSON export functionality
Capture summary with protocol statistics
Error handling and user-friendly output
Ethical use warnings and acknowledgment

🚀 Usage Examples:
bash# Basic usage (captures 10 packets)
python packet_analyzer.py

# Capture 50 packets with summary
python packet_analyzer.py -c 50 -s

# Capture and save to file
python packet_analyzer.py -c 20 -o captured_packets.json
⚠️ Important Notes:
System Requirements:

Requires root/administrator privileges for raw socket access
Run with sudo on Linux/Mac or as Administrator on Windows

Ethical Considerations:

The tool includes built-in ethical use warnings
Only use on networks you own or have explicit permission to monitor
Designed specifically for educational and learning purposes
Includes acknowledgment prompt before operation

Educational Value:

Demonstrates network protocol structure
Shows how packet capture works at a low level
Helps understand TCP/IP stack layers
Useful for cybersecurity and network administration learning

The tool emphasizes responsible use and includes multiple safeguards to ensure it's used ethically for educational purposes only.
