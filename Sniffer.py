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
        self.flag = 1
        self.lock = Lock()
        self.ap_list = dict()
        self.client_list = dict()
        self.cond = Condition(lock = self.lock)
        self.sniff = pcap(name = name, promisc = True, immediate = True, timeout_ms = 50)
        self.pkt = self.sniff.readpkts()
        self.size = len(self.pkt)
        self.max_num = 99
        self.total = 0

    '''
        Filter out and sort packets as either a client or access point.
        @param num: Unique numerical identifier given to a thread
    '''
    def filter(self, num):
        # Run until all indices in self.pkt have been examined
        while True:
            self.lock.acquire()

            # Sleep until threads turn to run
            while self.flag != num:
                self.cond.wait()

            # Done criteria met, kill thread.
            if self.max_num > self.size:
                if num == self.max_num:
                    self.max_num -= 1
                    self.flag = self.max_num
                    self.cond.notify_all()
                    self.lock.release()
                    return None

                self.flag = self.max_num
                self.cond.notify_all()
                self.lock.release()

            # Work to do
            else:
                pk = self.pkt[self.size - num][1]
                offset, rt_data = radiotap_parse(pk)

                # Broadcast-type of packet (signifies an access point)
                if pk[offset] == 0x80:
                    self.total += 1
                    iEE_offset, ap_info = ieee80211_parse(pk, offset)
                    start = iEE_offset + 14

                    # SSID
                    ssid = (pk[start: start + pk[iEE_offset + 13]]).decode()
                    # Power
                    pwr = rt_data['dbm_antsignal']
                    # MAC address
                    mac = ap_info['addr3']
                    # Add new item to dictionary
                    if ssid not in self.ap_list:
                        self.ap_list[ssid] = AccessPoint(pwr, mac, ssid)

                # Remove element from list, decrement list size
                self.pkt.pop(self.size - num)
                self.size -= 1

                # Set values for next thread to run
                if self.flag == self.max_num:
                    self.flag = 1
                else:
                    self.flag += 1

                # Release lock, wake up threads
                self.cond.notify_all()
                self.lock.release()


    '''
        Creates a set number of threads that are used
        to listen for and sort incoming packets.
    '''
    def createThread(self):
        thread_array = [Thread(target = self.filter, args = (i, )) for i in range(1, self.max_num + 1)]

        for thread in thread_array:
            thread.start()

        for t in thread_array:
            t.join()
