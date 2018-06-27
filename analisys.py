from ntethernet import *              # class
from ntsaveSession import *           # class

import dpkt                         # sniff lib
import pcap                         # sniff lib


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


def runSniff(pc, decode):
    try:
        for ts, pkt in pc:
            pkt = str(decode(pkt))

            dest_mac, src_mac, eth_proto, data = ethernet_frame(pkt)                            # header frame
            version, dest_ip, src_ip, proto, TTL, checksum, flags, offset, ID, totalLength, TOS, IHL, data = packet_ipv4(
                data)                                                                           # frame infos

            return dest_mac, src_mac, eth_proto, version, dest_ip, src_ip, proto, TTL, checksum, flags, offset, ID, \
                    totalLength, TOS, IHL, data

    except KeyboardInterrupt:
        nrecv, ndrop, nifdrop = pc.stats()
        print('\n%d packets received by filter' % nrecv)
        print('%d packets dropped by kernel' % ndrop)

def writeResult(dest_mac, src_mac, eth_proto, version, dest_ip, src_ip, proto, TTL, checksum, flags, offset, ID, \
                    totalLength, TOS, IHL, data ,project_dir, stFormatted, nr):
    result = str(nr) + '\nEthernet Frame:\n' + TAB_1 + "Destination MAC: {}\n".format(dest_mac) + TAB_1 + \
             "Source MAC: {}\n".format(src_mac) + TAB_1 + "Protocol: {}\n".format(eth_proto) + TAB_2 + \
             "Version: {}\n".format(version) + TAB_2 + "Header Length: {}".format(str(IHL * 4)) + " bytes\n" + \
             TAB_2 + "Destination IP: {}\n".format(dest_ip) + TAB_3 + "Geo: {}\n".format(get_ip_location(dest_ip)) \
             + TAB_2 + "Source IP: {}\n".format(src_ip) + TAB_3 + "Geo: {}\n".format(get_ip_location(src_ip)) \
             + TAB_2 + "Protocol: {}\n".format(proto) + TAB_2 + "Type of Service: {}\n".format(getTOS(TOS)) + TAB_2 + \
             "Lenght: {}\n".format(str(totalLength)) + TAB_2 + "ID: {}".format(str(hex(ID))) + " ({}".format(
        str(ID)) + ")\n" \
             + TAB_2 + "Flag: \n\t\t\t{}".format(getFlags(flags)) + '\n' + TAB_2 + "Fragment offset: {}\n".format(
        str(offset)) \
             + TAB_2 + "TTL: {}\n".format(str(TTL)) + TAB_2 + "Checksum: {}\n".format(
        str(checksum)) + TAB_2 + "Payload: {}\n".format(data[20:])

    write_file(project_dir + '/' + stFormatted + '.pcap', result)  # write all in the session file log