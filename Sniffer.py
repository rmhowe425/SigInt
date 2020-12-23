from pcap import pcap
from Src.Filter import Filter

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
            while True:
                pkt = self.sniff.__next__()[1]

                print("{}\nAP MAC: {}\nClient MAC: {}\nSSID: {}\n\n".format(num, Filter.getAPMAC(pkt), Filter.getCLIMAC(pkt),
                                                                         Filter.getSSID(pkt)))
                num += 1
        except Exception as e:
            print("Error Sniffing packets\n{}".format(str(e)))

