from automata.s5.S5_config import *
from automata.s5.s5_server_atmt import *

class s5_server(object):
    def __init__(self, dmac, smac, sref, iface):
        self.s5_server_atmt = None
        self.is_stopped =False
        self.cotp_params = S5_COTP_Params(dmac, smac, sref, iface)
        self._sever_cotp_socket = COTPSocket(dmac=dmac, smac=smac, sref=sref, iface=iface)

    def accept_order(self):
        self.s5_server_atmt = S5_SERVER_ATMT(sever_cotp_skt=self._sever_cotp_socket)
        self.s5_server_atmt.run()

