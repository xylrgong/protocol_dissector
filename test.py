from scapy.layers.l2 import Dot3, LLC
from protocols.cotp import *
from scapy.utils import hexdump
from automata.cotp.cotp_automaton import *
from automata.cotp.cotp_socket import *
from config import *
from protocols.h1 import *
from automata.s5.s5_socket import*
from automata.s5.S5_config import*
from automata.s5.s5_server import *

import binascii


def main():
    skt = s5_server(dmac='00:30:6e:0c:87:4e', smac='08:00:06:1a:11:11', sref=0x0c01,
                     iface='以太网 2')
    skt.accept_order()
    # skt = COTPSocket(dmac='00:30:6e:0c:87:4e', smac='08:00:06:1a:11:11', sref=0x0c01,
    #                  iface='以太网')
    # skt.accept()
    # # pkt = skt.recv_data_block(1)
    # # h1_pkt = dissect_h1_ex(*pkt)
    # # print(h1_pkt.Opcode)
    time.sleep(99999)
    pass
#      hexPKTstr = str(binascii.b2a_hex(bytes(*pkt, encoding="utf8")))
#      hexDWNRstr = hexPKTstr[22: 22 + len]

if __name__ == "__main__":
    main()
    pass
