# MIT License – see LICENSE file © 2025 Daniel Cochavi
# ----------------------------------------------------
# UDP Echo ↔ Sniffer Mitigation PoC

import socket
import sys

HOST = ''
PORT = 12321  # Arbitrary non-privileged port

# hard-coded number for the xor group
d = 5

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
Name:   byte_to_char
Input:  8 bytes as binary e.g '01101000'
Output: char represented by binary e.g '01101000' return 'h'
'''


def byte_to_char(byt):
    return chr(binary_to_int(byt))


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


'''
Name:   xor_binary_array
Input:  binary array e.g ['10110010', '00110101', ...]
Output: the xor result
'''


def xor_binary_array(binary_array):
    return reduce(lambda a, b: ''.join('0' if i == j else '1' for i, j in zip(a, b)), binary_array)


'''
Name:   fix_msg
Input:  e packet index, missing index, the whole packets
Output: the missing packet
'''


def fix_msg(index, index_to_fix, msg_dict):
    packets_list = []
    # run over d group
    for key in range(msg_dict[index][1], msg_dict[index][2] + 1):
        if key != index_to_fix:
            packets_list.append(msg_dict[key][1])

    packets_list.append(msg_dict[index][3])

    # create the missing packet
    packet_list = [2, xor_binary_array(packets_list)]

    return packet_list


'''
Name:   get_message
Input:  all of the packets
Output: the whole message as string
'''


def get_message(msg_dict):
    index_list = []
    new_dict = dict()

    # run over all the packets
    for key in msg_dict:
        counter = 0
        index_to_fix = None
        # if it's an e packet
        if msg_dict[key][0] == 1:
            # check if all d packets exist
            for key2 in range(int(msg_dict[key][1]), int(msg_dict[key][2]) + 1):
                # if there are missing packets
                if not msg_dict.has_key(key2):
                    counter += 1
                    index_to_fix = key2
            # fix the missing packet
            if counter == 1:
                new_dict[index_to_fix] = fix_msg(key, index_to_fix, msg_dict)

        new_dict[key] = msg_dict[key]
    for key in new_dict:
        index_list.append(key)

    # create the string to return the client
    msg_s = ""
    for index in index_list:
        if new_dict[index][0] != 1:
            msg_s += binary_to_string(new_dict[index][1])

    return msg_s


'''
The section bellow open a socket and receive/send messages from/to a client.
'''
# Datagram (udp) socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    print 'Socket created'
except socket.error, msg:
    print 'Failed to create socket. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

# Bind socket to local host and port
try:
    s.bind((HOST, PORT))
except socket.error, msg:
    print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

print 'Socket bind complete'

# now keep talking with the client
while True:
    message_dict = dict()
    stop_receive = True
    packet = None
    addr = None
    # receive data from client (data, addr)
    while True:
        res = s.recvfrom(512)
        packet = res[0]
        addr = res[1]

        # if this is the last packet
        if len(packet) == 8 and binary_to_int(packet) == 3:
            break

        # assemble each packet
        tmp_type = binary_to_int(packet[:8])
        i = binary_to_int(packet[8:40])
        message_dict.setdefault(i, [])
        message_dict[i].append(tmp_type)

        if tmp_type != 1:
            message_dict[i].append(packet[40:])
        else:
            message_dict[i].append(binary_to_int(packet[40:72]))
            message_dict[i].append(binary_to_int(packet[72:104]))
            message_dict[i].append(packet[104:])

        # if this is the last packet
        if tmp_type == 3:
            # For the last packet.
            res = s.recvfrom(512)
            break

    if len(message_dict) != 0:
        reply = get_message(message_dict)
        message_dict.clear()
    else:
        reply = ''

    # return the message to the client
    s.sendto(reply, addr)
    print 'Message[' + addr[0] + ':' + str(addr[1]) + '] - ' + reply.strip()

s.close()
