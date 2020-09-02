from utils.base_automaton import *
from automata.cotp.cotp_config import *
from proxy.proxy_stack import *
import threading


class _NetworkIF_ATMT(BaseAutomaton):
    def construct(self):
        self.trans = [(s('BEGIN', initial=1) >> s('LISTENING')),
                      (s('LISTENING') >> s('END', final=1)) + cond(func=self._recv, recv_pkt=1)]

    def forward(self, pkt):
        self.send(pkt)

    def master_filter(self, pkt):
        return COTP_Base in pkt

    def _recv(self, pkt):
        self.out_queue.append_pkt(dissect_cotp(pkt))
        return False

    def parse_args(self, **kwargs):
        log.debug("代理层初始化参数...")
        self.iface = kwargs.pop('iface', '')
        log.info("代理层网络接口: " + self.iface)
        BaseAutomaton.parse_args(self, debug=0, iface=self.iface, **kwargs)


class ProxyManager(object):
    def __init__(self, *args, **kwargs):
        self.netif = _NetworkIF_ATMT(*args, **kwargs)
        self.flow_hmap = {}

    def run(self):
        self.netif.runbg()

        _t = threading.Thread(target=self._run)
        _t.start()

    def _run(self):
        while True:
            # 阻塞式接收数据包
            pkt = self.netif.out_queue.recv_pkt_block(1)[0]
            conn = COTP_Connection(dmac=pkt.dst, smac=pkt.src)

            # 计算每流哈希值
            hkey = conn.get_hash()

            pst = None
            no_process = False
            # 如果是新流
            if hkey not in self.flow_hmap:
                if COTP_CR in pkt:
                    # 分配数据结构
                    pst = ProxyStackS5()
                    self.flow_hmap[hkey] = pst
                else:
                    # 奇怪的包，不处理直接转发
                    self.netif.forward(pkt)
                    no_process = True
            # 如果流已有记录
            else:
                pst = self.flow_hmap[hkey]

            # 下发到每流的代理协议栈
            if not no_process:
                # 如果协议栈未处理，直接转发
                if not pst.process_pkt(pkt):
                    self.netif.forward(pkt)

            # 转发处理后的数据包
            # 这些数据包是由协议栈处理后送入网络接口的发送队列
            if self.netif.in_queue.size() > 0:
                pkt_list = self.netif.in_queue.recv_pkt()
                for pkt in pkt_list:
                    self.netif.forward(pkt)
