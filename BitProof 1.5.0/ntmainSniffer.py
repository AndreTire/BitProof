from ntethernet import *              # class
from ntsaveSession import *           # class

import dpkt                         # sniff lib
import pcap                         # sniff lib

import socket                       # socket lib

import time                         # time lib
import datetime                     # datetime lib


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


ROOT_DIR = 'capture'
create_dir(ROOT_DIR)


def snifferMain():
    # Get host
    host = socket.gethostbyname(socket.gethostname())
    print('IP: {}'.format(host))

    # New pcap instance for WinSock
    name = None
    pc = pcap.pcap(name)
    decode = { pcap.DLT_LOOP:dpkt.loopback.Loopback,
               pcap.DLT_NULL:dpkt.loopback.Loopback,
               pcap.DLT_EN10MB:dpkt.ethernet.Ethernet }[pc.datalink()]

    # Try to create a new directory and file
    try:
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') + '\n'           # file name
        stFormatted = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H-%M-%S')         # directory name
        project_dir = ROOT_DIR + '/' + stFormatted
        create_dir(project_dir)

        write_file(project_dir + '/' + stFormatted + '.pcap', st)                               # .pcap file
        print('listening on %s: %s' % (pc.name, pc.filter))

        # Start sniffing packet in the backbone who work with standard 802.3 and 802.11
        for ts, pkt in pc:
            pkt = str(decode(pkt))

            dest_mac, src_mac, eth_proto, data = ethernet_frame(pkt)                            # header frame
            version, dest_ip, src_ip, proto, TTL, checksum, flags, offset, ID, totalLength, TOS, IHL, data = packet_ipv4(
                data)                                                                           # frame infos

            result = '\nEthernet Frame:\n' + TAB_1 + "Destination MAC: {}\n".format(dest_mac) + TAB_1 + \
                     "Source MAC: {}\n".format(src_mac) + TAB_1 + "Protocol: {}\n".format(eth_proto) + TAB_2 + \
                     "Version: {}\n".format(version) + TAB_2 + "Header Length: {}".format(str(IHL * 4)) + " bytes\n" + \
                     TAB_2 + "Destination IP: {}\n".format(dest_ip) + TAB_3 + "Geo: {}\n".format(get_ip_location(dest_ip))\
                     + TAB_2 + "Source IP: {}\n".format(src_ip) + TAB_3 + "Geo: {}\n".format(get_ip_location(src_ip)) \
                     + TAB_2 + "Protocol: {}\n".format(proto) + TAB_2 + "Type of Service: {}\n".format(getTOS(TOS)) + TAB_2 + \
                     "Lenght: {}\n".format(str(totalLength)) + TAB_2 + "ID: {}".format(str(hex(ID))) + " ({}".format( str(ID) ) + ")\n" \
                     + TAB_2 + "Flag: \n\t\t\t{}".format(getFlags(flags)) + '\n' + TAB_2 + "Fragment offset: {}\n".format(str(offset)) \
                     + TAB_2 + "TTL: {}\n".format(str(TTL)) + TAB_2 + "Checksum: {}\n".format(str(checksum)) + TAB_2 + "Payload: {}\n".format(data[20:])

            write_file(project_dir + '/' + stFormatted + '.pcap', result)                       # write all in the session file log


            print('\nEthernet Frame:')
            # Header
            print(TAB_1 + "Destination MAC: {}".format(dest_mac))
            print(TAB_1 + "Source MAC: {}".format(src_mac))
            print(TAB_1 + "Protocol: {}".format(eth_proto))

            # Frame
            print(TAB_2 + "Version: {}".format(version))
            print(TAB_2 + "Header Length: {}".format(str(IHL * 4)) + " bytes")
            print(TAB_2 + "Destination IP: {}".format(dest_ip))
            print(TAB_3 + "Geo: {}".format(get_ip_location(dest_ip)))
            print(TAB_2 + "Source IP: {}".format(src_ip))
            print(TAB_3 + "Geo: {}".format(get_ip_location(src_ip)))
            print(TAB_2 + "Protocol: {}".format(proto))
            print(TAB_2 + "Type of Service: {}".format(getTOS(TOS)))
            print(TAB_2 + "Lenght: {}".format(str(totalLength)))
            print(TAB_2 + "ID: {}".format(str(hex(ID))) + " ({}".format( str(ID) ) + ")")
            print(TAB_2 + "Flag: \n\t\t\t{}".format(getFlags(flags)))
            print(TAB_2 + "Fragment offset: {}".format(str(offset)))
            print(TAB_2 + "TTL: {}".format(str(TTL)))
            print(TAB_2 + "Checksum: {}".format(str(checksum)))
            print(TAB_2 + "Payload: {}".format(data[20:]))

            return dest_mac, src_mac, eth_proto, version, dest_ip, src_ip, proto, TTL, checksum, flags, offset, ID, \
                    totalLength, TOS, IHL, data

    except KeyboardInterrupt:
        nrecv, ndrop, nifdrop = pc.stats()
        print('\n%d packets received by filter' % nrecv)
        print('%d packets dropped by kernel' % ndrop)


if __name__ == '__main__':
    snifferMain()