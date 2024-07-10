import socket
import struct
import time

def checksum(source_string):
    countTo = (len(source_string) // 2) * 2
    sum = 0
    count = 0

    while count < countTo:
        thisVal = source_string[count + 1] * 256 + source_string[count]
        sum = sum + thisVal
        sum = sum & 0xffffffff
        count = count + 2

    if countTo < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def create_icmp_packet(seq_number):
    icmp_type = 8  # ICMP Echo Request
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = 0
    header = struct.pack('bbHHh', icmp_type, icmp_code, icmp_checksum, icmp_id, seq_number)
    data = struct.pack('d', time.time())
    icmp_checksum = checksum(header + data)
    header = struct.pack('bbHHh', icmp_type, icmp_code, socket.htons(icmp_checksum), icmp_id, seq_number)
    packet = header + data
    return packet

def traceroute(hostname, max_hops=30, timeout=2):
    dest_addr = socket.gethostbyname(hostname)
    port = 33434
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')
    ipList = []

    for ttl in range(1, max_hops + 1):
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        recv_socket.settimeout(timeout)
        recv_socket.bind(("", port))

        icmp_packet = create_icmp_packet(ttl)
        send_socket.sendto(icmp_packet, (hostname, port))
        send_time = time.time()

        try:
            data, curr_addr = recv_socket.recvfrom(512)
            curr_addr = curr_addr[0]
            elapsed_time = (time.time() - send_time) * 1000  # in milliseconds
            ipList.append(curr_addr)
            
            if curr_addr == dest_addr:
                break
        except socket.timeout:
            print(f"{ttl}\t*\tRequest timed out.")
        finally:
            send_socket.close()
            recv_socket.close()

    return ipList