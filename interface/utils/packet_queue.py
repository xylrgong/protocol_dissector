from scapy.packet import Packet
from collections import deque
import threading


class PacketQueue(object):
    def __init__(self):
        self._queue = deque()
        self._signal = threading.Event()

    # 向队列写入数据包
    def append_pkt(self, pkt):
        assert isinstance(pkt, Packet)
        self._queue.append(pkt)
        self._signal.set()

    # 从队列读取数据包，取得最多 size 个数的数据包
    def recv_pkt(self, size=0):
        result = []
        if size <= 0:
            size = len(self._queue)
        while len(self._queue) > 0 and len(result) < size:
            result.append(self._queue.popleft())
        return result

    # 从队列读取数据包，阻塞式接口，在接收了 size 个数的数据包前一直等待
    def recv_pkt_block(self, size=0):
        result = []
        if size <= 0:
            return self.recv_pkt(size)
        while len(result) < size:
            if len(self._queue) == 0:
                self._signal.clear()
                self._signal.wait()
            result.append(self._queue.popleft())
        return result

    def size(self):
        return len(self._queue)
