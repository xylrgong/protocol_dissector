from scapy.layers.l2 import Dot3, LLC
from protocols.cotp import *
from scapy.utils import hexdump
from automata.cotp.cotp_automaton import *


def main():
    cotp_atmt = COTP_Automaton(is_server=True,
                               dmac='11:22:33:44:55:66', smac='11:22:33:44:55:66',
                               dref=0, sref=0)
    cotp_atmt.run()

    pass


if __name__ == "__main__":
    main()
    pass
