from ntbit2Info import *                                                                              # class
from socket import *                                                                                # class

from geolite2 import geolite2                                                                       # geocal lib

import struct                                                                                       # lib for bit -> string
import binascii                                                                                     # lib for bit -> string


# Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6s2s', data[:14])                                  # destination MAC, source MAC, # protocol of IP
    return get_mac(binascii.hexlify(dest_mac)), get_mac(binascii.hexlify(src_mac)), get_proto(
        binascii.hexlify(proto)), data[14:]                                                         # format the bytes


# Unpack IPv4 and other part of frame
def packet_ipv4(data):
    packet = struct.unpack('!BBHHHBBH4s4s', data[:20])                                              # unpack packet
    version_IHL = packet[0]
    version = version_IHL >> 4                                                                      # version of the IP
    IHL = version_IHL & 0xF                                                                         # internet header length
    TOS = packet[1]                                                                                 # type of service
    totalLength = packet[2]
    ID = packet[3]                                                                                  # identification
    flags = packet[4]                                                                               # flag
    offset = packet[4] & 0x1FFF                                                                     # offset
    TTL = packet[5]                                                                                 # time to live
    proto = packet[6]                                                                               # protocol of communication
    checksum = packet[7]                                                                            # CRC-32
    src_ip = inet_ntoa(packet[8])                                                                   # source IP
    dest_ip = inet_ntoa(packet[9])                                                                  # destination IP

    return version, dest_ip, src_ip, get_proto(str(proto)), TTL, checksum, flags, offset, ID, totalLength, TOS, IHL, data[20:]

# Geolocate the ip inside the ethernet packet, from library geolite2, SQL lib
def get_ip_location(ip):
    reader = geolite2.reader()                                                                      # reader for ip
    location = reader.get(ip)                                                                       # dns resolver

    try:
        country = location["country"]["names"]["en"]                                                # get the country in 'en' type
    except:
        country = "Unknown"

    try:
        subdivision = location["country"]["subdivision"][0]["names"]["en"]                         # get the subdivision in 'en' type
    except:
        subdivision = "Unknown"

    try:
        city = location["city"]["names"]["en"]                                                     # get the city in 'en' type
    except:
        city = "Unknown"

    return country, subdivision, city