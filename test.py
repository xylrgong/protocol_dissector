from scapy.layers.l2 import Dot3, LLC
from protocols.cotp import *
from scapy.utils import hexdump
from automata.cotp.cotp_automaton import *
from automata.cotp.cotp_socket import *
from config import *


def main():
    skt = COTPSocket(dmac='00:30:6e:0c:87:4e', smac='08:00:06:1a:11:11', sref=0x0c01,
                     iface='本地连接* 1')
    skt.accept()

    print(skt.recv_data_block(2))
    time.sleep(99999)

    pass


if __name__ == "__main__":
    main()
    pass
