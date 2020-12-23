from Src.Sniffer import Sniffer

def main():
    packet = Sniffer("../Artifacts/LargePacketCapture.pcapng")
    packet.sniffPacket()

main()