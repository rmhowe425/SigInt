from pcap import pcap
from Src.radtiotap.radiotap import radiotap_parse, ieee80211_parse

class Sniffer:

    '''
        Constructor for Sniffer class.
        @param name: Name of adapter / file to read packets from.
    '''
    def __init__(self, name = None):
        self.sniff = pcap(name = name, promisc = True, immediate = True, timeout_ms = 50)

    '''
        Records an unlimited number of packets.
    '''
    def sniffPacket(self):

        num = 1

        try:
            pkt = self.sniff.readpkts()
            num = 1

            for pk in pkt:
                offset = radiotap_parse(pk[1])[0]
                print("{})  {}".format(num, ieee80211_parse(pk[1], offset)))
                num += 1
        except Exception as e:
            print("Error Sniffing packets\n{}".format(str(e)))

