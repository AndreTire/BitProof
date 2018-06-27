import dpkt                         # sniff lib
import pcap                         # sniff lib
import socket


def initWinSock():
    # Get host
    host = socket.gethostbyname(socket.gethostname())
    print('IP: {}'.format(host))

    # New pcap instance for WinSock
    name = None
    pc = pcap.pcap(name)
    decode = {pcap.DLT_LOOP: dpkt.loopback.Loopback,
              pcap.DLT_NULL: dpkt.loopback.Loopback,
              pcap.DLT_EN10MB: dpkt.ethernet.Ethernet}[pc.datalink()]
    print('listening on %s: %s' % (pc.name, pc.filter))
    return pc, decode