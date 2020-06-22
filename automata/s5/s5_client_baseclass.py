from automata.cotp.cotp_socket import *
from automata.s5.S5_config import *
from protocols.h1 import *


class S5_CLIENT_ATMT_Baseclass(BaseAutomaton):
    def __init__(self, *args, **kwargs):
        BaseAutomaton.__init__(self, *args, **kwargs)
        self.nooferr = 0
        self.is_dconnected = False


    def send_dwnr(self, dwnr):
        pkt = H1(*h1_payload[dwnr][0]) / hex_bytes(h1_payload[dwnr][1])
        print(dwnr)
        self.cotp_skt.send_data(raw(pkt))

    def get_cond(self, dwnr, func_name):
        def _is_dwnr():
            buf = self.cotp_skt.recv_data_block(1)
            h1_pkt = dissect_h1_ex(*buf)
            pkt_DWNR = int.from_bytes(h1_pkt.Address_within_memory_block, byteorder='big')
            log.debug('收到序列号：{}'.format(pkt_DWNR))
            return pkt_DWNR == dwnr
        _is_dwnr.__name__ = func_name
        return _is_dwnr

    # def verifyDWNR(self, pkt, dwnr):
    #     h1_pkt = dissect_h1_ex(*pkt)
    #     pkt_DWNR = int.from_bytes(h1_pkt.Address_within_memory_block, byteorder='big')
    #     log.debug('收到序列号：{}'.format(pkt_DWNR))
    #     return pkt_DWNR == dwnr

