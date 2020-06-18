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
from scapy.fields import *
from automata.s5.s5_socket import *
from automata.s5.S5_config import *
from scapy.compat import chb
from scapy.layers.l2 import Dot3, LLC
from utils.utils import *
import logging as log


def main():
    skt = s5Socket(dmac='08:00:06:1a:11:11', smac='00:30:6e:0c:87:4e', sref=0x01,
                     iface='以太网')
    skt.send_command("aa101", "open")
    time.sleep(1)
    #skt.send_data(int.to_bytes(20, 2, 'big'))
    time.sleep(2)
<<<<<<< HEAD
=======
    skt.send_data('abccc333\x00')
>>>>>>> 8362b7112bc83a56e21d71aec4f27f6dfb9c538c
    time.sleep(3)
    time.sleep(99999)
    pass


if __name__ == "__main__":
    main()
    pass
