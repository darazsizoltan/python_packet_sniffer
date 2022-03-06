import socket
import struct


MAX_BUFFER_SIZE = 65535
ETHERNET_PROTOCOL_IPV4 = 8



# What is a socket?
# Socket is an endpoint of communication chanel used by programs to send data.
# The data can travel back and forth locally or across the internet.
# Sockets have two primary params to controll the way they send data:
#   Address family: OSI network layer protocol
#   Socket type: transport layer protocol

# create an INET raw socket
# 1st param: address family (forexample: ipv4, ipv6..)
# 2nd param: Type of the sockets -> RAW sockets allow a program 
#            define custom headers for specific protocols which 
#            are provided by the kernel by default
# 3rd param: protocol type -> This protocol number is defined by the Internet 
#                             Assigned Numbers Authority (IANA). 
#                             We have to be aware of the family of the socket.
#                             then we can only choose a protocol.

def main(): 
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True: 
        # Recvfrom method in the socket module returns all the data from the socket.
        # Param is the maximum buffer size.    
        raw_data, addr = s.recvfrom(MAX_BUFFER_SIZE)
        dest_mac, src_mac, ethernet_protocol, data = ethernet_frame_human_readable(raw_data)
        print('\nEthernet frame:')
        print('Destination MAC address: {}, Source MAC address: {}, Protocol: {}'.format(dest_mac, src_mac, ethernet_protocol))
        if ethernet_protocol == ETHERNET_PROTOCOL_IPV4:
            version, header_length, ttl, ip_protocol, src, target, data = ipv4_head_decode(data)
            print( '\t - ' + 'IPv4 Packet:') 
            print('\t\t - ' + 'Version: {}, Header Length: {}, TTL: {},'.format(version, header_length, ttl)) 
            print('\t\t - ' + 'Protocol: {}, Source: {}, Target: {}'.format(ip_protocol, get_ip_addr_human_readable(src), get_ip_addr_human_readable(target)))
        
        print('Raw data: {}'.format(data))

# Parsing the packet
# What is a packet?
#   ----------------------------------------------------------    -----------------
#   |  -------------------  --------------  --------------   |    |   ----------  |  ------------
#   |  | Destination MAC |  | Source MAC |  | Ether Type |   |    |   |   IP    | |  | CRC      |
#   |  | 6 bytes         |  | 6 bytes    |  | 2 bytes    |   |    |   |         | |  | checksum |
#   |  -------------------  --------------  --------------   |    |   ----------  |  ------------
#   |                       MAC header (14 bytes)            |    |      DATA     |    4 bytes
#   |                                                        |    | 46-1500 bytes |
#   ----------------------------------------------------------    -----------------
# The first 6 bytes are Destination MAC address -> MAC of the package reciever
# The second 6 bytes are Source MAC address -> MAC of the package sender
# Ether type indicates which protocol is encapsulated in the payload of the ethernet frame
# Cyclic Redundancy Checks (CRC) and Checksums are two popular mechanisms to detect data corruption

def ethernet_frame_human_readable(raw_data):
    # Grab the first 14 bytes and upack it.
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', raw_data[:14])
    # Return 
    # The formated destination mac address, 
    # The formated source mac adress, 
    # The protocol in compatible format (big-endian or little-endian, whichever we need to use)
    #   ntohs converts a 16 bit integer from network format to host format.
    # The data after the first 14 bytes (We don't know how large the data is)
    return get_mac_addr_human_readable(dest_mac), get_mac_addr_human_readable(src_mac), socket.ntohs(proto), raw_data[14:]

# Mac address in a "human" readable format
def get_mac_addr_human_readable(bytes_addr):
    # Iterate through each chunk of the mac address i.e.:"AA:BB:CC:DD:EE:FF"
    # Format them to two decimal places and join them with a ":"
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# IP address in "human" readable format
def get_ip_addr_human_readable(addr): 
 return '.'.join(map(str, addr))



# The IP header has a welll defined structure:
# Protocol Version (four bits): The first four bits. This represents the current IP protocol. 
# Header Length (four bits): The length of the IP header is represented in 32-bit words. Since 
#   this field is four bits, the maximum header length allowed is 60 bytes. Usually the value is 5, 
#   which means five 32-bit words: 5 * 4 = 20 bytes. 
# Type of Service (eight bits): The first three bits are precedence bits, the next four bits represent
#   the type of service, and the last bit is left unused. 
# Total Length (16 bits): This represents the total IP datagram length in bytes. This a 16-bit field.
#   The maximum size of the IP datagram is 65,535 bytes. 
# Flags (three bits): The second bit represents the Don't Fragment bit. When this bit is set, the 
#   IP datagram is never fragmented. The third bit represents the More Fragment bit. If this bit is 
#   set, then it represents a fragmented IP datagram that has more fragments after it. 
# Time To Live (eight bits): This value represents the number of hops that the IP datagram will 
# go through before being discarded. 
# Protocol (eight bits): This represents the transport layer protocol that handed over data to the IP layer. 
# Header Checksum (16 bits): This field helps to check the integrity of an IP datagram. 
# Source and destination IP (32 bits each): These fields store the source and destination address, respectively.
#   0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |Version|  IHL  |Type of Service|          Total Length         |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |         Identification        |Flags|      Fragment Offset    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  Time to Live |    Protocol   |         Header Checksum       |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                       Source Address                          |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Destination Address                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Options                    |    Padding    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
def ipv4_head_decode(raw_data): 
    version_header_length = raw_data[0]
    # Bitwise operation, shit right 4 bits. We're left with only the version.
    version = version_header_length >> 4 
    # We need the header length so we know where the data starts
    # a = 50 ->    110010
    # b = 25 ->    011001
    # c = a & b -> 010000
    # c = 16
    header_length = (version_header_length & 15) * 4 
    # ! = byte order, network, big-endian
    # x = no value
    # B = integer
    # s = bytes
    ttl, ip_protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20]) 
    return version, header_length, ttl, ip_protocol, src, target, raw_data[header_length:] 




main()