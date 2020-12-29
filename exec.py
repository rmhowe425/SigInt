from time import time
from Src.Sniffer import Sniffer

def main():
    start = time()
    packet = Sniffer("../Artifacts/LargePacketCapture.pcapng")
    packet.createThread()

    print("Elapsed time: {}".format(round(time() - start, 2)))
main()