# MIT License – see LICENSE file © 2025 Daniel Cochavi
# ----------------------------------------------------
# UDP Echo ↔ Sniffer Mitigation PoC

import time
import string
import random
from random import randint
import socket  # for sockets
import sys  # for exit

# hard-coded number for the xor group
d = 5

'''
Name:   char_to_byte
Input:  char
Output: byte representation
'''


def char_to_byte(char):
    return int_to_binary(ord(char), 8)


'''
Name:   int_to_binary
Input:  int
Output: binary representation
'''


def int_to_binary(integer, fill=32):
    if isinstance(integer, int):
        return "{0:b}".format(integer).zfill(fill)
    else:
        return False


'''
Name:   string_to_binary
Input:  string
Output: binary representation
'''


def string_to_binary(string):
    if isinstance(string, str):
        return ''.join(char_to_byte(char) for char in string)
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
Name:   split_binary_array_to_bytes
Input:  binary string e.g '000111101001010'
Output: split to size of 8 e.g '000111101001010' return '00011110', '01001010'
'''


def split_binary_array(binary_array, chunk_size):
    tmp_array = []
    split_array = []

    for n in range(0, len(binary_array), chunk_size):
        if n % d == 0:
            if len(tmp_array) != 0:
                split_array.append(tmp_array)
                tmp_array = []
        tmp_array.append((binary_array[n:n + chunk_size]).zfill(chunk_size))

    if tmp_array:
        split_array.append(tmp_array)

    return split_array


'''
Name:   assemble_e
Input:  d length packets list, e packet index
Output: assembled e packet
'''


def assemble_e(d_list, e_index):
    e_type = "00000001"
    first_p_i = int_to_binary(e_index + 1)
    last_p_i = int_to_binary(e_index + len(d_list))
    e_packet = xor_binary_array(d_list)

    # return the assembled e packet
    return e_type + int_to_binary(e_index) + first_p_i + last_p_i + e_packet


'''
Name:   assemble_p
Input:  d length packets list, e packet index
Output: assembled packets
'''


def assemble_p(d_list, e_index):
    d_packets = []
    p_type = "00000010"
    # assemble each packet and append
    for n, data in enumerate(d_list):
        d_packets.append(p_type + int_to_binary(e_index + 1 + n) + data)

    return d_packets


'''
Name:   assemble_massage
Input:  string
Output: packets list
'''


def assemble_massage(message):
    if message == '':
        return None

    final_message = []
    binary_message = string_to_binary(message)
    # 408 bytes represent 51 characters
    binary_list = split_binary_array(binary_message, 408)

    # n to save the indexes
    n = 0
    for chunk in binary_list:
        # assemble e packet
        e = assemble_e(chunk, n)
        # assemble message packet
        p = assemble_p(chunk, n)
        final_message.append(e)
        for pack in p:
            final_message.append(pack)
        n += len(chunk) + 1
    final_message[len(final_message) - 1] = final_message[len(final_message) - 1][:7] + '1' + final_message[len(
        final_message) - 1][8:]

    return final_message


def create_random_input():
    num = randint(1, 1000)
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(num))

'''
The section bellow open a socket and receive/send messages from/to a server.
'''
# create dgram udp socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)

except socket.error:
    print 'Failed to create socket'
    sys.exit()

host = '127.0.0.1'
port = 12321

while True:
    # get message from user
    # msg = raw_input('Enter message to send : ')
    for _ in range(5):
        msg = create_random_input()
        binary_massage = assemble_massage(msg)
        time.sleep(.2)
        try:
            # send packets to the server
            if binary_massage is not None:
                for i, packet in enumerate(binary_massage):
                    if (d + i + 1) % (d + 1) != 1:
                        s.sendto(packet, (host, port))

            # create and send last packet to server
            stop_receive = "00000011"
            time.sleep(.2)
            s.sendto(stop_receive, (host, port))

            # receive data from client (data, addr)
            resp = s.recvfrom(1024)
            reply = resp[0]
            addr = resp[1]
            print 'Server reply : ' + reply
            time.sleep(3)
        except socket.error, msg:
            print 'Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()
    break
