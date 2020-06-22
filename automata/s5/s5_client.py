from automata.cotp.cotp_config import *
from automata.s5.S5_config import *
from automata.s5.s5_valve_client_atmt import *

class s5_client(object):
    def __init__(self, dmac, smac, sref, iface):
        self.dconnect_atmt = None
        self.valve_client_atmt = None
        self.ap_client =None
        self._cotp_skt = COTPSocket(dmac=dmac, smac=smac, sref=sref, iface=iface)

    def do_valve(self, valve_name='', op_type = ''):
        # 开启动态连接
        self.dconnect_atmt = S5_ATMT_DCONNECT(cotp_skt=self._cotp_skt)
        self.dconnect_atmt.run()
        # 开关阀门操作
        self.valve_client_atmt = S5_VALVE_OPERATE_ATMT(cotp_skt=self._cotp_skt, valve_name=valve_name, op_type=op_type)
        self.valve_client_atmt.run()
        # 开关阀门操作后进行复位操作
        self.valve_client_atmt = S5_VALVE_OPERATE_ATMT(cotp_skt=self._cotp_skt, valve_name=valve_name, op_type='reset')
        self.valve_client_atmt.run()

    def do_dis_dconnect(self):    # 关闭动态连接
        if self._cotp_skt.is_connected:
            self._cotp_skt.disconnect()
            log.debug('动态连接已断开')
        self._do_clear()

    def do_cotp_connect(self):
        if self._cotp_skt.is_connected == False:
            self._cotp_skt.connect()

    def _do_clear(self):
        self.dconnect_atmt = None
        self.valve_client_atmt = None





















