# MIT License – see LICENSE file © 2025 Daniel Cochavi
# ----------------------------------------------------
# UDP Echo ↔ Sniffer Mitigation PoC

from scapy.all import *


'''
Name:   binary_to_int
Input:  string
Output: string as binary

The function receive a string and return the binary representation.
'''


def binary_to_int(string):
    if isinstance(string, str):
        return int(string, 2)
    else:
        return False


'''
Name:   split_binary_array_to_bytes
Input:  binary string e.g '000111101001010'
Output: split to size of 8 e.g '000111101001010' return '00011110', '01001010'
'''


def split_binary_array_to_bytes(binary_array):
    split_array = []

    for i in range(0, len(binary_array), 8):
        split_array.append(binary_array[i:i + 8])

    return split_array


'''
Name:   byte_to_char
Input:  8 bytes as binary e.g '01101000'
Output: char represented by binary e.g '01101000' return 'h'
'''


def byte_to_char(byt):
    return chr(binary_to_int(byt))


'''
Name:   binary_to_string
Input:  binary string
Output: the string result e.g '0110100001101001' return 'hi'
'''


def binary_to_string(binary):
    if isinstance(binary, str):
        bin_list = split_binary_array_to_bytes(binary)
        return ''.join(byte_to_char(byt) for byt in bin_list)
    else:
        return False

# callback function to print the packet
def pkt_callback(pkt):
    print

    try:
        # check if the first characters are not 0 or 1
        count = 0
        for i in pkt.load:
            if count == 25:
                break
            if i != '0' and i != '1':
                print pkt.load
                return
            else:
                count+=1

        # check if last packet
        if len(pkt.load) == 8:
            if binary_to_int(pkt.load) == 3:
                print "End packet: " + pkt.load
                return
        # get packet type
        tmp_type = binary_to_int(pkt.load[:8])
        if tmp_type != 1 and tmp_type != 2 and tmp_type != 3:
            print pkt.load
            return

        # get packet index
        i = binary_to_int(pkt.load[8:40])
        print "Packet type: " + str(tmp_type)
        print "Packet index: " + str(i)

        if tmp_type != 1:
            print "Packet data: " + binary_to_string(pkt.load[40:])
        else:
            print "First index of e XOR: " + str(binary_to_int(pkt.load[40:72]))
            print "Last index of e XOR: " + str(binary_to_int(pkt.load[72:104]))
            print "Packet XOR data: " + pkt.load[104:]

        print
    except AttributeError:
        print "Empty payload"


# create sniffer
sniff(iface="lo", prn=pkt_callback, filter="udp and host 127.0.0.1 and port 12321", store=0)
