from pcap import pcap
from Src.AccessPoint import AccessPoint
from threading import Thread, Lock, Condition
from Src.radtiotap.radiotap import radiotap_parse, ieee80211_parse

class Sniffer:

    '''
        Constructor for Sniffer class.
        @param name: Name of adapter / file to read packets from.
    '''
    def __init__(self, name = None):
        self.size = 1
        self.lock = Lock()
        self.cond = Condition(lock = self.lock)
        self.ap_list = dict()
        self.client_list = dict()
        self.sniff = pcap(name = name, promisc = True, immediate = True, timeout_ms = 50)

    '''
        Filter out and sort packets as either a client or access point.
        @param pk: Packet to be inspected
    '''
    def filter(self, pk):
        offset, rt_data = radiotap_parse(pk)

        # Broadcast packet
        if pk[offset] == 0x80:
            iEE_offset, ap_info = ieee80211_parse(pk, offset)
            start = iEE_offset + 14

            # SSID
            ssid = (pk[start: start + pk[iEE_offset + 13]]).decode()
            # Power
            pwr = rt_data['dbm_antsignal']
            # MAC address
            mac = ap_info['addr3']

            # Add new item to dictionary
            self.lock.acquire()
            self.ap_list[ssid] = AccessPoint(pwr, mac, ssid)
            self.lock.release()

    '''
        Records an unlimited number of packets.
    '''
    def sniffPacket(self):
        thread_array = []

        try:
            pkt = self.sniff.readpkts()

            for pk in pkt:
                t = Thread(target = self.filter, args = (pk[1], ))
                t.start()
                thread_array.append(t)
                self.size += 1
                
        except Exception as e:
            print("Error Sniffing packets\n{}".format(str(e)))

        for t in thread_array:
            t.join()
