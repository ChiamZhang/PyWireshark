import time
from queue import Queue

from scapy import all as cap

queue=Queue()
def sniff_action(self, packet):
    if not self.sniffer:
        return
    queue.put(packet)

if __name__ == '__main__':
    s=cap.AsyncSniffer(
        iface='Intel(R) Wi-Fi 6E AX210 160MHz ',
        prn=sniff_action,
        # filter=exp,
    )
    s.start()
    time.sleep(10)

    s.stop()

    for i in queue:
        print(i)