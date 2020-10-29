from automata.cotp.cotp_config import *
from automata.s5.S5_config import *
from automata.s5.s5_valve_client_atmt import *
from automata.s5.s5_ap_client_atmt import *


class s5_client(object):
    def __init__(self, dmac, smac, sref, iface):
        self.dconnect_atmt = None
        self.valve_client_atmt = None
        self.ap_client_atmt =None
        self.is_running = False    # 控制器运行状态
        self.s5_params = S5_COTP_Params(dmac, smac, sref, iface)
        self.valve_cotp_skt = None
        self.ap_cotp_skt = None

    # TODO: 注释，添加参数说明
    # valva_name支持的取值
    # op_type支持的取值
    def do_valve(self, valve_name='', op_type = ''):
        self.valve_cotp_skt = self.get_cotp_skt()
        # 开启动态连接
        if self.dconnect_atmt == None:
            self.dconnect_atmt = S5_ATMT_DCONNECT(cotp_skt=self.valve_cotp_skt)
            self.dconnect_atmt.run()
        # 开关阀门操作
        self.valve_client_atmt = S5_VALVE_OPERATE_ATMT(cotp_skt=self.valve_cotp_skt, valve_name=valve_name, op_type=op_type)
        self.valve_client_atmt.run()
        # 开关阀门操作后进行复位操作
        log.debug('15s后准备进行复位操作...20s')
        time.sleep(15)
        self.valve_client_atmt = S5_VALVE_OPERATE_ATMT(cotp_skt=self.valve_cotp_skt, valve_name=valve_name, op_type='reset')
        self.valve_client_atmt.run()

    # 若AP状态为关闭，则该操作启动控制器，反之亦然
    def do_ap(self):
        self.ap_cotp_skt = self.get_cotp_skt()
        self.ap_client_atmt = S5_ATMT_AP_OPERATE(cotp_skt=self.ap_cotp_skt, is_starting=not self.is_running, ap_callback=self.operate_ap)
        self.ap_client_atmt.run()

    def do_dis_dconnect(self):    # 关闭动态连接
        if self.valve_cotp_skt.is_connected:
            self.valve_cotp_skt.disconnect()
            log.debug('动态连接已断开')
        self._do_clear()

    def do_cotp_connect(self):
        if self.valve_cotp_skt.is_connected == False:
            self.valve_cotp_skt.connect()

    def _do_clear(self):
        self.dconnect_atmt = None
        self.valve_client_atmt = None

    def operate_ap(self):
        if not self.is_running:
            s5_client.ap_running = True
        else:
            s5_client.ap_running = False

    def get_cotp_skt(self):
        return COTPSocket(dmac=self.s5_params.dmac, smac=self.s5_params.smac, sref=self.s5_params.sref, iface=self.s5_params.iface)

