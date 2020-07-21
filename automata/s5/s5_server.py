from automata.s5.S5_config import *
from automata.s5.s5_server_atmt import *

class s5_server(object):
    def __init__(self, dmac, smac, sref, iface):
        self.s5_server_atmt = None
        self.is_stopped = False
        self.cotp_params = S5_COTP_Params(dmac, smac, sref, iface)
        self._sever_cotp_socket1 = self.get_cotp_skt(dmac, smac, sref, iface)
        self._sever_cotp_socket2 = self.get_cotp_skt(dmac, smac, sref, iface)
        self._sever_cotp_socket3 = self.get_cotp_skt(dmac, smac, sref, iface)


    def accept_order(self):
        self.s5_server_atmt = S5_SERVER_ATMT(sever_cotp_skt=self._sever_cotp_socket1,sever_cotp_skt2=self._sever_cotp_socket2,sever_cotp_skt3=self._sever_cotp_socket3, _is_stopped=self.is_stopped,ap_callback= self.operate_ap)
        self.s5_server_atmt.run()

    def operate_ap(self):
        if not self.is_stopped:
            s5_server.is_stopped = True
        else:
            s5_server.is_stopped = False

    def get_cotp_skt(self,dmac, smac, sref, iface):
        return COTPSocket(dmac=dmac, smac=smac, sref=sref, iface=iface)