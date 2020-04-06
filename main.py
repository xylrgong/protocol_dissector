from scapy.layers.l2 import Dot3, LLC
from protocols.cotp import *
from scapy.utils import hexdump


def main():

    cotp_pkt2 = Dot3(dst='11:22:33:44:55:66', src='11:22:33:44:55:66') /\
        LLC(dsap=0xfe, ssap=0xfe, ctrl=0x03) /\
        CLNP() /\
        COTP(pdu_name='DT_TPDU')
    # cotp_pkt2.show()
    # hexdump(cotp_pkt2)

    print('\n@@@@@@@@@@@\n')

    cotp_pkt = Dot3(dst='11:22:33:44:55:66', src='11:22:33:44:55:66') /\
        LLC(dsap=0xfe, ssap=0xfe, ctrl=0x03) /\
        CLNP() /\
        COTP(pdu_name='CR_TPDU', params=[
            ('VP_CHECKSUM', 0x1234), 'VP_TPDU_SIZE', 'VP_VERSION_NR',
            'VP_OPT_SEL', ('VP_SRC_TSAP', 'S5_PGDIR'), ('VP_DST_TSAP', 'Eop')
        ])
    # cotp_pkt.show()
    # hexdump(cotp_pkt)

    print('\n@@@@@@@@@@@\n')

    pkt_hex = '0800061a111100306e0c874e003cfefe030027e80000400242c302cc6bc0010ac40101c60103c10853355f5047444952c20853355f504744495253351001030f060a2020202020202020'
    pkt_buffer = bytes.fromhex(pkt_hex)
    pkt2 = dissect_cotp(pkt_buffer)
    pkt2.show()
    hexdump(pkt2)

    pass


if __name__ == "__main__":
    main()
    pass
