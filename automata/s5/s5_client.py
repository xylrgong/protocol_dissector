from automata.cotp.cotp_config import *
from automata.s5.S5_config import *
from automata.s5.s5_valve_client_atmt import *

class s5_client(object):
    def __init__(self, dmac, smac, sref, iface):
        self.dconnect_atmt = None
        self.valve_client_atmt = None
        self.ap_client =None
        self.cotp_params = S5_COTP_Params(dmac, smac, sref, iface)

    def do_valve(self, valve_name='', op_type = ''):
        self.dconnect_atmt = S5_ATMT_DCONNECT(params=self.cotp_params)
        self.dconnect_atmt.runbg()
        print(self.dconnect_atmt.cotp_skt._params.your_tpdunr)
        if not self.valve_client_atmt:
            self.valve_client_atmt = S5_VALVE_OPERATE_ATMT(valve_name=valve_name, op_type=op_type)
        else:setattr(self.valve_client_atmt, '_op_type', op_type)
        self.valve_client_atmt.runbg()

    def do_dis_dconnect(self):
        if self.valve_client_atmt:
            self.valve_client_atmt.cotp_skt.disconnect()
            log.debug('动态连接已断开')




















