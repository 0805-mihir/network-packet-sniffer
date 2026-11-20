# Network Packet Sniffer

## Overview

Network Packet Sniffer is a Python-based cybersecurity project designed to capture and analyze IPv4 network packets using raw sockets.

It captures network traffic and extracts important information such as source IP address, destination IP address, protocol type, port numbers, and packet size.

The application displays a short packet capture summary in the terminal and stores detailed packet information in a log file named `network_log.txt`.

## Features

- Real-time network packet capturing.
- IPv4 packet header analysis.
- Source and destination IP address extraction.
- TCP, UDP, ICMP, and other protocol identification.
- TCP and UDP source and destination port extraction.
- Packet size monitoring.
- Protocol-wise traffic statistics.
- Detailed packet logging in a text file.
- Graceful packet capture termination using Ctrl + C.

## Technologies Used

- Python 3.12.4
- Visual Studio Code
- Socket Module
- Struct Module
- Datetime Module
- Collections Module

## Project Structure

```text
Network-Packet-Sniffer/
│
├── packet_sniffer.py
├── network_log.txt
├── Network_Packet_Sniffer_Report.pdf
└── README.md
```

## Requirements

- Python 3.x
- Windows 10 / Windows 11
- Visual Studio Code or any Python editor
- Active network connection
- Administrator privileges for raw socket packet capturing on Windows

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/0805-mihir/network-packet-sniffer.git
```

### Step 2: Open Project Folder

```bash
cd network-packet-sniffer
```

### Step 3: Run the Program

Run the following command in the terminal with Administrator privileges:

```bash
python packet_sniffer.py
```

## Working Process

1. The program detects the local IP address.
2. It creates a raw IPv4 socket.
3. It starts capturing network packets.
4. It analyzes the IPv4 packet headers.
5. It identifies the network protocol.
6. It extracts TCP and UDP port information.
7. It displays packet capture progress in the terminal.
8. It saves detailed packet information in `network_log.txt`.
9. It displays final traffic statistics when the user presses Ctrl + C.

## Sample Output

```text
=============================================
          NETWORK PACKET SNIFFER
=============================================

[+] Local IP Address: 10.98.207.72
[+] Packet Capture Started!
[+] Detailed logs: network_log.txt
[+] Press CTRL + C to stop capturing.

[+] Captured 25 packets
[+] Captured 50 packets
[+] Captured 75 packets

[+] Capture stopped by user.

========== TRAFFIC SUMMARY ==========
Total Packets: 450
TCP: 410
UDP: 40
=====================================

[+] Log File: network_log.txt
[+] Network Packet Sniffer Finished.
```

## Project Results

During testing, the application successfully captured 450 network packets.

| Protocol | Packets Captured |
|---|---:|
| TCP | 410 |
| UDP | 40 |
| **Total** | **450** |

The captured packet information was successfully stored in `network_log.txt`.

## Limitations

- Currently supports IPv4 packet capturing.
- Requires administrator privileges on Windows.
- Does not perform deep packet inspection.
- Does not decrypt encrypted network traffic.
- Uses a command-line interface.

## Future Enhancements

- IPv6 packet support.
- Graphical user interface.
- Advanced protocol analysis.
- Packet filtering by IP address and port.
- Network traffic visualization.
- CSV and JSON export functionality.
- Real-time monitoring dashboard.

## Learning Outcomes

- Understanding network packet structures.
- Learning raw socket programming in Python.
- Understanding IPv4, TCP, and UDP protocols.
- Learning packet header analysis.
- Understanding network traffic monitoring.
- Improving practical cybersecurity skills.

## Disclaimer

This project is developed for educational and cybersecurity learning purposes only.

Use this tool only on networks and devices that you own or have explicit authorization to monitor.

## Author

**Mihir Koshti**

GitHub: [0805-mihir](https://github.com/0805-mihir)

## License

This project is intended for educational purposes.
