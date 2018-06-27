# Format MAC address (AA:BB:CC:DD:EE:FF)
def get_mac(mac):
    mac_addr = mac[:2] + ':' + mac[2:-8] + ':' + mac[4:-6] + ':' + mac[6:-4] + ':' + mac[8:-2] + ':' + mac[-2:]
    return mac_addr.upper()

# Format Protocol
def get_proto(proto):
    protofile = open('Protocol.txt', 'r')                                   # open the Protocol.txt file in read mode
    p = '255	reserved'                                                   # default statement for unknown protocol
    try:                                                                    # try to convert str into int
        proto = int(proto)
    except ValueError:                                                      # if error put proto in unknown protocol
        proto = 255

    if proto == 800:                                                        # if proto is IPv4 packet
        p = protofile.readline(16)
    else:                                                                   # different protocol
        proto = proto + 2
        for x, line in enumerate(protofile):                                # read file line by line
            if x == proto:                                                  # line is the proto
                p = line

    p = p.split(",")                                                        # get only the first infos
    protofile.close()                                                       # close file
    return p[0]                                                             # return the infos

# get Type of Service: 8 bits
def getTOS(data):
    precedence = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash", 4: "Flash override", 5: "CRITIC/ECP",
                  6: "Internetwork control", 7: "Network control"}
    delay = {0: "Normal delay", 1: "Low delay"}
    throughput = {0: "Normal throughput", 1: "High throughput"}
    reliability = {0: "Normal reliability", 1: "High reliability"}
    cost = {0: "Normal monetary cost", 1: "Minimize monetary cost"}

    #   get the 3rd bit and shift right
    D = data & 0x10
    D >>= 4

    #   get the 4th bit and shift right
    T = data & 0x8
    T >>= 3

    #   get the 5th bit and shift right
    R = data & 0x4
    R >>= 2

    #   get the 6th bit and shift right
    M = data & 0x2
    M >>= 1

    #   the 7th bit is empty and shouldn't be analyzed

    tabs = '\n\t\t\t'
    TOS = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + \
          reliability[R] + tabs + cost[M]
    return TOS


# get Flags: 3 bits
def getFlags(data):
    flagR = {0: "0 - Reserved bit"}
    flagDF = {0: "0 - Fragment if necessary", 1: "1 - Do not fragment"}
    flagMF = {0: "0 - Last fragment", 1: "1 - More fragments"}

    #   get the 1st bit and shift right
    R = data & 0x8000
    R >>= 15

    #   get the 2nd bit and shift right
    DF = data & 0x4000
    DF >>= 14

    #   get the 3rd bit and shift right
    MF = data & 0x2000
    MF >>= 13

    tabs = '\n\t\t\t'
    flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
    return flags