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
    skt = COTPSocket(dmac='08:00:06:1a:11:11', smac='00:30:6e:0c:87:4e', sref=0x01,
                     iface='WLAN')
    skt.connect()
    time.sleep(1)
    skt.send_data(int.to_bytes(1, 2, 'big'))
    time.sleep(2)
    skt.send_data('abccc333')
    time.sleep(3)
    skt.disconnect()

    time.sleep(99999)
    pass


if __name__ == "__main__":
    main()
    pass
