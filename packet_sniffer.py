
import socket
import struct
import datetime
from collections import Counter

# ==========================================
#       NETWORK PACKET SNIFFER
# ==========================================

LOG_FILE = "network_log.txt"

packet_count = 0
protocol_count = Counter()


# ==========================================
#          LOGGING FUNCTION
# ==========================================

def log_message(message):
    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(message + "\n")


# ==========================================
#          PROTOCOL NAME
# ==========================================

def get_protocol(protocol_number):
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }

    return protocols.get(protocol_number, "OTHER")


# ==========================================
#          PACKET PROCESSING
# ==========================================

def process_packet(packet):

    global packet_count

    if len(packet) < 20:
        return

    try:
        ip_header = struct.unpack("!BBHHHBBH4s4s", packet[:20])

        version_ihl = ip_header[0]
        version = version_ihl >> 4
        header_length = (version_ihl & 15) * 4

        if version != 4 or header_length < 20:
            return

        if len(packet) < header_length:
            return

        total_length = ip_header[2]
        protocol_number = ip_header[6]

        source_ip = socket.inet_ntoa(ip_header[8])
        destination_ip = socket.inet_ntoa(ip_header[9])

        protocol = get_protocol(protocol_number)

        fragment_offset = ip_header[4] & 0x1FFF

        packet_count += 1
        protocol_count[protocol] += 1

        source_port = "-"
        destination_port = "-"

        transport_data = packet[header_length:]

        # TCP Header
        if protocol_number == 6 and fragment_offset == 0:
            if len(transport_data) >= 20:
                tcp_header = struct.unpack(
                    "!HHLLBBHHH",
                    transport_data[:20]
                )

                source_port = tcp_header[0]
                destination_port = tcp_header[1]

        # UDP Header
        elif protocol_number == 17 and fragment_offset == 0:
            if len(transport_data) >= 8:
                udp_header = struct.unpack(
                    "!HHHH",
                    transport_data[:8]
                )

                source_port = udp_header[0]
                destination_port = udp_header[1]

        timestamp = datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # Detailed information saved in file
        log_message("----------------------------------------")
        log_message(f"Time: {timestamp}")
        log_message(f"Packet Number: {packet_count}")
        log_message(f"Source IP: {source_ip}")
        log_message(f"Destination IP: {destination_ip}")
        log_message(f"Protocol: {protocol}")
        log_message(f"Source Port: {source_port}")
        log_message(f"Destination Port: {destination_port}")
        log_message(f"Packet Size: {len(packet)} bytes")
        log_message("----------------------------------------")

        # Limited terminal output
        if packet_count % 25 == 0:
            print(
                f"[+] Captured {packet_count} packets | "
                f"Latest: {source_ip} -> {destination_ip} | "
                f"Protocol: {protocol}"
            )

    except (struct.error, OSError, IndexError):
        pass


# ==========================================
#          TRAFFIC STATISTICS
# ==========================================

def show_statistics():

    print("\n========== TRAFFIC SUMMARY ==========")
    print(f"Total Packets: {packet_count}")

    for protocol, count in protocol_count.items():
        print(f"{protocol}: {count}")

    print("=====================================")

    log_message("\n========== TRAFFIC SUMMARY ==========")
    log_message(f"Total Packets: {packet_count}")

    for protocol, count in protocol_count.items():
        log_message(f"{protocol}: {count}")

    log_message("=====================================")


# ==========================================
#          MAIN FUNCTION
# ==========================================

def main():

    raw_socket = None
    capture_started = False

    print("=============================================")
    print("          NETWORK PACKET SNIFFER")
    print("=============================================")

    # Create a fresh log file
    with open(LOG_FILE, "w", encoding="utf-8") as file:
        file.write("NETWORK PACKET SNIFFER LOG\n")
        file.write("Capture Started: " +
                   datetime.datetime.now().strftime(
                       "%Y-%m-%d %H:%M:%S"
                   ) + "\n\n")

    try:
        # Detect local IP address
        temp_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        try:
            temp_socket.connect(("8.8.8.8", 80))
            local_ip = temp_socket.getsockname()[0]
        finally:
            temp_socket.close()

        print(f"[+] Local IP Address: {local_ip}")

        # Create raw socket
        raw_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_IP
        )

        raw_socket.bind((local_ip, 0))

        # Enable packet capture (Windows)
        raw_socket.ioctl(
            socket.SIO_RCVALL,
            socket.RCVALL_ON
        )

        raw_socket.settimeout(1)

        capture_started = True

        print("[+] Packet Capture Started!")
        print("[+] Detailed logs: " + LOG_FILE)
        print("[+] Press CTRL + C to stop capturing.\n")

        log_message("[+] Packet Capture Started")

        while True:
            try:
                packet, address = raw_socket.recvfrom(65535)
                process_packet(packet)

            except socket.timeout:
                continue

    except KeyboardInterrupt:
        print("\n[+] Capture stopped by user.")

    except OSError as error:
        if getattr(error, "winerror", None) == 10013:
            print("\n[!] Permission denied.")
            print("[!] Run VS Code as Administrator.")
        else:
            print(f"\n[!] Socket Error: {error}")

    except Exception as error:
        print(f"\n[!] Error: {error}")

    finally:

        if raw_socket is not None:

            if capture_started:
                try:
                    raw_socket.ioctl(
                        socket.SIO_RCVALL,
                        socket.RCVALL_OFF
                    )
                except OSError:
                    pass

            raw_socket.close()

        show_statistics()

        print(f"\n[+] Log File: {LOG_FILE}")
        print("[+] Network Packet Sniffer Finished.")


# ==========================================
#          PROGRAM START
# ==========================================

if __name__ == "__main__":
    main()
