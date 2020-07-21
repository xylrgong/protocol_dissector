from automata.cotp.cotp_atmt import *
from automata.cotp.cotp_config import *
from automata.s5.s5_atmt import *
from automata.s5.S5_config import *
from collections import deque
from automata.cotp.cotp_socket import *
import threading
from utils.utils import *
from config import *

###################
#  这个文件已弃用    #
###################


class s5Socket(object):
    # 连接到主机，阻塞式接口
    # 断开连接
    def send_command(self, device_name, command_name):
        self._do_connect()
        if device_name == "AP101":
            return self._ap_operate(equip=device_name, set_status=command_name)
        elif device_name in OPERATE_DATA:
            return self._do_operate(equip=device_name, set_status=command_name)
        else :
            log.debug("设备名称不合法")

    def wait_command(self):
        self._accept()

    def __init__(self, dmac, smac, sref, iface):
        self.is_connected = False
        self._params = S5_Params()
        self._params.iface = iface
        self._params.conn = COTP_Connection(dmac=dmac, smac=smac, sref=sref)
        self._atmt_connect = None
        self._atmt_operate = None
        self._atmt_server = None

    def _clear(self):
        self.is_connected = False
        if self._atmt_connect:
            self._atmt_connect.stop()
            self._atmt_connect = None
        if self._atmt_operate:
            self._atmt_operate.stop()
            self._atmt_operate = None
        if self._atmt_server:
            self._atmt_server.stop()
            self._atmt_server = None


    def _do_connect(self):
        self._clear()
        self._atmt_connect = S5_ATMT_DConnect()
        self._atmt_connect.run()
        nooferr = self._atmt_connect.errno
        if not nooferr:
            self.is_connected = True
        else:
            self._report_error(self._atmt_connect.errno, '动态连接失败')
        return nooferr

    def _do_disconnect(self):
        if self.is_connected:
            atmt_close = S5_ATMT_Disconnect()
            atmt_close.runbg()

    def _do_operate(self, equip, set_status):
        if not self.is_connected:
            return 201
        atmt_operate=S5_ATMT_OPERATE(equip=equip, set_status=set_status)
        atmt_operate.run()
        nooferr = atmt_operate.errno
        self._params = atmt_operate.params
        if nooferr:
            self._report_error(self._atmt_connect.errno, '发送失败')
        set_status = 'set_reset'
        atmt_operate = S5_ATMT_OPERATE(equip=equip, set_status=set_status)
        atmt_operate.run()
        nooferr = atmt_operate.errno
        self._params = atmt_operate.params
        if nooferr:
            self._report_error(self._atmt_connect.errno, '发送失败')
        return nooferr

    def _ap_operate(self, equip, set_status):
        self._clear()
        self._atmt_operate = S5_ATMT_AP_OPERATE()

    def _accept(self):
        self._clear()
        self._atmt_server = S5_ATMT_S5_SERVER()
        self._atmt_server.runbg()


    @staticmethod
    def _report_error(nooferr, description):
        log.debug('{}：{}, {}'.format(description, nooferr, H1_ERR_CODE[nooferr]))


