from automata.cotp.cotp_automaton import *
from automata.cotp.cotp_config import *
from utils.utils import *


class COTPSocket(object):
    def __init__(self, dmac, smac, sref, iface):
        self._conn = COTP_Connection(dmac=dmac, smac=smac, sref=sref)
        self._atmt = COTP_Automaton(dmac=dmac, smac=smac, sref=sref, iface=iface)
        self._callback_connected = None
        self._callback_disconnected = None
        self._callback_error = None
        self._callback_recv = None

        self._atmt.regist_callbacks(self._atmt_connected,
                                    self._atmt_disconnected,
                                    self._atmt_error,
                                    self._atmt_recv)

    # 注册回调函数，在到达相应状态时，这些函数会被调用
    def regist_callbacks(self,
                         callback_connected=None,
                         callback_disconnected=None,
                         callback_error=None,
                         callback_recv=None):
        self._callback_connected = callback_connected
        self._callback_disconnected = callback_disconnected
        self._callback_error = callback_error
        self._callback_recv = callback_recv

    # 连接到主机，异步函数
    def connect(self):
        self._atmt.is_server = False
        self._atmt.runbg()

    # 断开连接，异步函数
    def disconnect(self):
        self._atmt.disconnect()

    # 发送数据，阻塞式接口
    def send_data(self, buf):
        self._atmt.send_bytes(buf)

    # 开始接收数据包
    def listen(self):
        self._atmt.is_server = True
        self._atmt.runbg()

    # ATMT通知函数
    def _atmt_connected(self):
        if self._callback_connected is not None:
            self._callback_connected()

    def _atmt_disconnected(self):
        if self._callback_disconnected is not None:
            self._callback_disconnected()

    def _atmt_error(self, errno):
        if self._callback_error is not None:
            self._callback_error(errno)

    def _atmt_recv(self, data):
        if self._callback_recv is not None:
            self._callback_recv(data)

