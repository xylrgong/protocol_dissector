from protocols.cotp import *
from automata.cotp.cotp_config import *
from utils.base_automaton import *
from proxy.proxy_stack_item import *


class ProxyCOTPParams(object):
    def __init__(self):
        self.is_client = False
        self.conn = COTP_Connection()
        self.your_tpdunr = 0
        self.my_tpdunr = 0
        self.your_credit = 0
        self.my_credit = 0
        self.cause = 0


class ProxyCOTPBase(BaseAutomaton):
    def __init__(self, *args, **kwargs):
        BaseAutomaton.__init__(self, *args, **kwargs)
        self.errno = 0
        self.params = ProxyCOTPParams()


class ProxyCOTPConnect(ProxyCOTPBase):
    def construct(self):
        self.trans = [
            (s('PROXY_COTP_CONNECT_BEGIN', initial=1) >> s('CONNECTION_CLOSED')),
            (s('CONNECTION_CLOSED') >> s('ACCEPT_CR')) + wait4(self._accept_cr),
            (s('ACCEPT_CR') >> s('ACCEPT_CC')) + wait4(self._accept_cc),
            (s('ACCEPT_CC') >> s('ACCEPT_CC_AK')) + wait4(self._accept_cc_ak),
            (s('ACCEPT_CC_AK') >> s('PROXY_COTP_CONNECTION_OPEN', final=1))
        ]

    def is_connected(self):
        return self.state.final

    def _accept_cr(self, pkt):
        conn = self.params.conn
        conn.dmac = pkt.dst
        conn.smac = pkt.src
        conn.sref = pkt.sref
        self.params.my_credit = pkt.pdutype & 0x0f
        return 0x00

    def _accept_cc(self, pkt):
        self.params.conn.dref = pkt.sref
        self.params.your_credit = pkt.pdutype & 0x0f
        return 0x00

    def _accept_cc_ak(self, pkt):
        self.params.your_tpdunr = pkt.tpdunr
        return 0x00


class ProxyCOTPData(ProxyCOTPBase):
    def construct(self):
        self.trans = [
            (s('PROXY_COTP_DATA_BEGIN', initial=1) >> s('WAIT_FOR_DT')),
            (s('WAIT_FOR_DT') >> s('ACCEPT_DT')) + wait4(),
            (s('ACCEPT_DT') >> s('ACCEPT_DT_AK')) + wait4(),
            (s('ACCEPT_DT_AK') >> s('WAIT_FOR_DT')),
        ]


class ProxyCOTPDisconnect(ProxyCOTPBase):
    def construct(self):
        self.trans = [
            (s('PROXY_COTP_DISCONNECT_BEGIN', initial=1) >> s('WAIT_FOR_DR')),
            (s('WAIT_FOR_DR') >> s('ACCEPT_DR')) + wait4(),
            (s('ACCEPT_DR') >> s('ACCEPT_DC')) + wait4(),
            (s('ACCEPT_DC') >> s('PROXY_COTP_DISCONNECT_END', final=1)),
        ]


class ProxyCOTPManager(ProxyStackItem):
    def __init__(self):
        self.atmt_connect = ProxyCOTPConnect()
        self.atmt_data = None
        self.atmt_disconnect = None

        self.atmt_connect.runbg()

    def process_pkt(self, pkt):
        if not self.atmt_connect.is_connected():
            self.atmt_connect.in_queue.append_pkt(pkt)
        else:
            pass
            return False
        return True
