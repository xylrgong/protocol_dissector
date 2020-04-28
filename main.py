from scapy.layers.l2 import Dot3, LLC
from protocols.cotp import *
from scapy.utils import hexdump
from automata.cotp.cotp_automaton import *
from automata.cotp.cotp_socket import *
from automata.cotp.cotp_config import *
from config import *
from utils.base_automaton import *
from tests.test_atmt import *


def main():
    skt = COTPSocket(dmac='11:22:33:44:55:66', smac='11:22:33:44:55:99', sref=0x01,
                     iface='Killer E2400 Gigabit Ethernet Controller #2')
    skt.connect()
    time.sleep(1)
    skt.send_data('abccc')
    skt.send_data('abccc333')
    time.sleep(3)
    skt.disconnect()

    time.sleep(99999)
    pass


if __name__ == "__main__":
    main()
    pass
