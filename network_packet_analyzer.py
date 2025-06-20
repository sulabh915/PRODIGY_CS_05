# packet_sniffer.py
import socket
import struct
import textwrap
import argparse
from collections import Counter
from prettytable import PrettyTable

protocol_counter = Counter()

# Mapping of common port numbers to protocol names
COMMON_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    22: "SSH",
    21: "FTP",
    23: "TELNET"
}

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def main():
    parser = argparse.ArgumentParser(description="Python Packet Sniffer (Linux only)")
    parser.add_argument('--log', action='store_true', help="Enable logging captured packets to a log file")
    args = parser.parse_args()

    if not hasattr(socket, 'AF_PACKET'):
        print("[-] This tool only runs on Linux using AF_PACKET sockets.")
        return

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("[*] Packet Sniffer Started (Ethical Use Only)")

    table = PrettyTable()
    table.field_names = ["Source IP", "Destination IP", "Protocol", "Src Port", "Dst Port", "Length", "TTL", "Info"]

    log_file = None
    if args.log:
        log_file = open("packet_log.txt", "w")
        log_file.write("\n=== Packet Capture Log ===\n")
        log_file.write("{:<15} {:<15} {:<10} {:<8} {:<8} {:<6} {:<5} {}\n".format(
            "Source IP", "Destination IP", "Protocol", "SrcPort", "DstPort", "Len", "TTL", "Info"))
        log_file.write("{}\n".format("-"*110))
        print("[+] Logging enabled: packet_log.txt")

    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            if len(raw_data) < 14:
                continue  # Ignore malformed packets

            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            if eth_proto != 0x0800:  # IPv4 only
                continue

            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))

            src_port, dest_port = "-", "-"
            info = ""

            if proto == 1:  # ICMP
                icmp_type, code, checksum, icmp_data = icmp_packet(data)
                info = f"ICMP Type={icmp_type} Code={code}"
            elif proto == 6:  # TCP
                src_port, dest_port, sequence, acknowledgment, _, _, tcp_data = tcp_segment(data)
                proto_name = COMMON_PORTS.get(dest_port, proto_name)
                try:
                    http_payload = tcp_data.decode(errors='ignore')
                    if http_payload.startswith("GET") or http_payload.startswith("POST"):
                        request_line = http_payload.split("\r\n")[0]
                        info += " | " + request_line
                        if http_payload.startswith("POST"):
                            headers, _, body = http_payload.partition("\r\n\r\n")
                            if body.strip():
                                info += f" | POST Data: {body.strip()[:100]}"
                except:
                    pass
                info = f"TCP Seq={sequence} Ack={acknowledgment} " + info
            elif proto == 17:  # UDP
                src_port, dest_port, length, udp_data = udp_segment(data)
                proto_name = COMMON_PORTS.get(dest_port, proto_name)
                info = f"UDP Length={length}"

            protocol_counter[proto_name] += 1

            packet_length = len(raw_data)
            table.add_row([src, target, proto_name, src_port, dest_port, packet_length, ttl, info])

            # Clear screen and print updated table
            print("\033c", end="")  # ANSI escape sequence to clear terminal
            print("[*] Packet Sniffer Started (Ethical Use Only)")
            print(table)

            # Display top protocols as a table
            proto_table = PrettyTable()
            proto_table.field_names = ["Protocol", "Packets"]
            for proto, count in protocol_counter.most_common(10):
                proto_table.add_row([proto, count])
            print("\nTop Protocols:")
            print(proto_table)

            # Write to log if enabled
            if log_file:
                log_file.write("{:<15} {:<15} {:<10} {:<8} {:<8} {:<6} {:<5} {}\n".format(
                    src, target, proto_name, str(src_port), str(dest_port), str(packet_length), str(ttl), info))
                log_file.flush()

    except KeyboardInterrupt:
        if log_file:
            log_file.close()
        print("\n[*] Packet Sniffer Stopped")

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), proto, data[14:]

def get_mac_addr(bytes_addr):
    return ':'.join(format(b, '02x') for b in bytes_addr).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 0x0F) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgment, offset_reserved_flags, offset, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

if __name__ == "__main__":
    try:
        from prettytable import PrettyTable
    except ImportError:
        print("[-] Missing library: prettytable\nInstall it with: pip install prettytable")
        exit(1)
    main()
