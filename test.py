from scapy.layers.l2 import Dot3, LLC
from protocols.cotp import *
from scapy.utils import hexdump
from automata.cotp.cotp_automaton import *
from automata.cotp.cotp_socket import *
from config import *


def main():
    skt = COTPSocket(dmac='11:22:33:44:55:99', smac='11:22:33:44:55:66', sref=0x0c01,
                     iface='Killer E2400 Gigabit Ethernet Controller #2')
    skt.accept()

    time.sleep(3)
    print(skt.recv_data())
    time.sleep(99999)

    pass


if __name__ == "__main__":
    main()
    pass
