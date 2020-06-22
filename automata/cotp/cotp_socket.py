from automata.cotp.cotp_atmt import *
from automata.cotp.cotp_config import *
from collections import deque
import threading
from utils.utils import *
from config import *


class COTPSocket(object):
    # 连接到主机，阻塞式接口
    def connect(self):
        return self._do_connect(is_passive=False)

    # 断开连接
    def disconnect(self):
        self._do_disconnect()

    # 发送数据，阻塞式接口
    def send_data(self, buf):
        assert(isinstance(buf, bytes) or isinstance(buf, str))
        return self._do_send(buf)

    # 接收数据包，读取最多 size 个数的数据包
    def recv_data(self, size=0):
        result = []
        if size <= 0:
            size = len(self._recv_queue)
        while len(self._recv_queue) > 0 and len(result) < size:
            result.append(self._recv_queue.popleft())
        return result

    # 接收数据包，阻塞式接口，在接收了 size 个数的数据包前一直等待
    def recv_data_block(self, size=0):
        result = []
        if size <= 0:
            return self.recv_data(size)
        while len(result) < size:
            if len(self._recv_queue) == 0:
                self._signal.clear()
                self._signal.wait()
            result.append(self._recv_queue.popleft())
        return result

    # 等待主机连接，阻塞式接口
    def accept(self):
        return self._do_connect(is_passive=True)

    def __init__(self, dmac, smac, sref, iface):
        self.is_connected = False
        self._params = COTP_Params()
        self._params.iface = iface
        self._params.conn = COTP_Connection(dmac=dmac, smac=smac, sref=sref)
        self._atmt_connect = None
        self._atmt_recv = None
        self._recv_queue = deque()
        self._signal = threading.Event()

    def _clear(self):
        self.is_connected = False
        if self._atmt_connect:
            self._atmt_connect.stop()
            self._atmt_connect = None
        if self._atmt_recv:
            self._atmt_recv.stop()
            self._atmt_recv = None

    def _do_connect(self, is_passive=False):
        self._clear()
        self._params.is_passive = is_passive
        self._atmt_connect = COTP_ATMT_Connect(params=self._params)
        self._atmt_connect.run()
        errno = self._atmt_connect.errno
        if not errno:
            self.is_connected = True
            self._do_recv()
            time.sleep(0.2)
        else:
            self._report_error(self._atmt_connect.errno, '连接失败')
        return errno

    def _do_disconnect(self):
        if self.is_connected:
            self._params.cause = 0x80
            atmt_close = COTP_ATMT_Disconnect(params=self._params)
            atmt_close.runbg()

    def _do_send(self, buf):
        if not self.is_connected:
            return 201
        atmt_send = COTP_ATMT_Send(params=self._params, data=buf)
        atmt_send.run()
        errno = atmt_send.errno
        if errno:
            self._report_error(self._atmt_connect.errno, '发送失败')
        return errno

    def _do_recv(self):
        self._atmt_recv = COTP_ATMT_Receive(params=self._params,
                                            recv_callback=self._recv_pkt,
                                            close_callback=self._disconnected)
        self._atmt_recv.runbg()

    def _recv_pkt(self, pkt):
        self._recv_queue.append(pkt)
        self._signal.set()

    def _disconnected(self):
        self._clear()

    @staticmethod
    def _report_error(errno, description):
        log.debug('{}：{}, {}'.format(description, errno, COTP_ERR_CODE[errno]))
