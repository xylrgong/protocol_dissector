from automata.cotp.cotp_socket import *
from automata.s5.S5_config import *
from protocols.h1 import *


class S5_SERVER_ATMT_Baseclass(BaseAutomaton):
    def __init__(self, *args, **kwargs):
        BaseAutomaton.__init__(self, *args, **kwargs)
        self.nooferr = 0

    def get_cond(self, dwnr, func_name):
        def _is_dwnr():
            buf = self.server_cotp_skt.recv_data_block(1)
            h1_pkt = dissect_h1_ex(*buf)
            pkt_DWNR = int.from_bytes(h1_pkt.Address_within_memory_block, byteorder='big')
            log.debug('收到序列号：{}'.format(pkt_DWNR))
            return pkt_DWNR == dwnr
        _is_dwnr.__name__ = func_name
        return _is_dwnr


    def send_pkt(self,dwnr):
        pkt = H1(*h1_server_payload[dwnr][0]) / hex_bytes(h1_server_payload[dwnr][1])
        self.server_cotp_skt.send_data(raw(pkt))

    def send_dwnr(self, dwnr, dwnr2=None, dwnr3=None):
        self.send_pkt(dwnr)
        print(dwnr)
        if dwnr2:
            self.send_pkt(dwnr2)
            print(dwnr2)
        if dwnr3:
            self.send_dwnr(dwnr3)
            print(dwnr3)












