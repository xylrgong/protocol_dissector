from scapy.layers.l2 import Dot3, LLC
from protocols.cotp import *
from scapy.utils import hexdump
from automata.cotp.cotp_automaton import *
from automata.cotp.cotp_socket import *
from automata.cotp.cotp_config import *
from config import *
from utils.base_automaton import *
from tests.test_atmt import *
from protocols.h1 import *
from scapy.packet import Packet, bind_layers, Raw, Padding
from automata.s5.s5_server_atmt import*
from automata.s5.s5_valve_client_atmt import*
from automata.s5.s5_server import *
from automata.s5.s5_client import *

from scapy.compat import chb
from scapy.layers.l2 import Dot3, LLC
from utils.utils import *
import logging as log


def main():
    skt = s5_client(dmac='08:00:06:1a:11:11', smac='00:30:6e:0c:87:4e', sref=0x01,
                     iface='以太网')
    # skt.do_valve(valve_name='aa101', op_type='open')
    # skt.do_dis_dconnect()
    skt.do_ap()
    # skt = COTPSocket(dmac='08:00:06:1a:11:11', smac='00:30:6e:0c:87:4e', sref=0x01,
    #                   iface='以太网')
    # skt.connect()
    # # pkt = H1(opcode_name='Unknown')
    # # skt.send_data(raw(pkt))
    # skt.send_data('255352')
    # time.sleep(2)
    # skt.disconnect()
    # skt.connect()
    # skt.send_data('sfegr3')
    print('Sleeping...')
    time.sleep(99999)
    pass


if __name__ == "__main__":
    main()
    pass
