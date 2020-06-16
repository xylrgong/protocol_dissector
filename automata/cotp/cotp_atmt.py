from scapy.automaton import *
from scapy.utils import *
from utils.base_automaton import *
from protocols.cotp import *
from automata.cotp.cotp_config import *
from config import *
import threading


# COTP自动机的基类
class COTP_ATMT_Baseclass(BaseAutomaton):
    def __init__(self, *args, **kwargs):
        BaseAutomaton.__init__(self, *args, **kwargs)
        self.errno = 0
        self.n_pkt = 0
        threading.Timer(10, self._traffic_check).start()

    # 用法： Automaton初始化时会调用此函数, 以更新参数
    def parse_args(self, **kwargs):
        log.debug("初始化参数...")
        self.params = kwargs.pop('params', None)
        log.info("网络接口: " + self.params.iface)
        BaseAutomaton.parse_args(self, debug=0, iface=self.params.iface, **kwargs)  # 根据本机环境修改 iface

    # 用法： Automaton进入recveive_condition后, 收到 pkt 时, 会调用此函数, 作为全局数据包过滤
    def master_filter(self, pkt):
        self.n_pkt += 1
        return COTP_Base in pkt and pkt.src != self.params.conn.smac

    def _traffic_check(self):
        if self.n_pkt == 0:
            log.info("网络接口[{}]没有收到任何数据包，请检查 iface 设置，以及 Npcap 是否正常工作".format(self.params.iface))

    # 构造2层数据包
    def _l2_packet(self):
        return (COTP_Dot3(dst=self.params.conn.dmac, src=self.params.conn.smac) /
                LLC(dsap=0xfe, ssap=0xfe, ctrl=0x03) /
                CLNP())

    def _send_and_log(self, pkt):
        self.send(pkt)
        self._report_pkt(pkt)

    def _is_bound_to_this_connection(self, pkt):
        if COTP_DR in pkt or COTP_DC in pkt or COTP_CC in pkt:
            conn1 = self.params.conn
            conn2 = COTP_Connection(pkt.src, pkt.dst, pkt.sref, pkt.dref)
            return conn1 == conn2
        if COTP_DT in pkt or COTP_AK in pkt:
            conn = self.params.conn
            return pkt.dst == conn.smac and pkt.src == conn.dmac and pkt.dref == conn.sref
        return False

    @staticmethod
    def _report_pkt(pkt, recv=0):
        text = "收到 {}：{}"
        if not recv:
            text = "发送 {}：{}"
        log.debug(text.format(TPDU_TYPE[0][pkt.pdutype], hexstr(pkt, onlyhex=1)))


# COTP建立连接自动机
class COTP_ATMT_Connect(COTP_ATMT_Baseclass):
    def construct(self):
        self.trans = [
            (s('CONNECT_BEGIN', initial=1) >> s('ERROR_PARAM', error=1)) + cond(self._has_error_param),
            (s('CONNECT_BEGIN', initial=1) >> s('CONNECTION_CLOSE')) + cond(prio=1),
            # 客户端部分
            (s('CONNECTION_CLOSE') >> s('WAIT_FOR_CC')) +
            cond(lambda: not self.params.is_passive) + action(self._send_cr),
            (s('WAIT_FOR_CC') >> s('CONNECTION_OPEN')) +
            cond(self._is_right_cc, recv_pkt=1) + action(self._send_cc_ak),
            (s('WAIT_FOR_CC') >> s('ERROR_TIMEOUT', error=1)) + cond(timeout=COTP_TIMEOUT),
            # 服务端部分
            (s('CONNECTION_CLOSE') >> s('WAIT_FOR_CR')) + cond(lambda: self.params.is_passive),
            (s('WAIT_FOR_CR') >> s('WAIT_FOR_CC_AK')) +
            cond(self._recv_cr, recv_pkt=1) + action(self._send_cc),
            (s('WAIT_FOR_CC_AK') >> s('CONNECTION_OPEN')) + cond(self._is_right_cc_ak, recv_pkt=1),
            (s('WAIT_FOR_CC_AK') >> s('ERROR_TIMEOUT', error=1)) + cond(timeout=COTP_TIMEOUT),
            # 错误与结束
            (s('ERROR_PARAM', error=1) >> s('CONNECTION_OPEN_FAILED')),
            (s('ERROR_TIMEOUT', error=1) >> s('CONNECTION_OPEN_FAILED')) + action(self._set_timeout_errno),
            (s('CONNECTION_OPEN_FAILED') >> s('CONNECTION_CLOSE')) + cond(lambda: self.params.is_passive),
            (s('CONNECTION_OPEN_FAILED') >> s('END', final=1)) + cond(lambda: not self.params.is_passive),
            (s('CONNECTION_OPEN') >> s('END', final=1))
        ]

    def _has_error_param(self):
        conn = self.params.conn
        if conn.sref == 0x00:
            self.errno = 103
            log.warning('非法的本机ref：sref == 0x00')
            return True
        if not is_mac(conn.dmac):
            self.errno = 100
            log.warning('非法的目标mac：dmac == {}'.format(conn.dmac))
            return True
        if not is_mac(conn.smac):
            self.errno = 101
            log.warning('非法的本机mac：smac == {}'.format(conn.smac))
            return True
        return False

    def _send_cr(self):
        conn = self.params.conn
        pkt = self._l2_packet() / \
              COTP(pdu_name='CR_TPDU', dref=conn.dref, sref=conn.sref, params=[
                  ('VP_CHECKSUM', 0x1234), 'VP_TPDU_SIZE', 'VP_VERSION_NR',
                  'VP_OPT_SEL', ('VP_SRC_TSAP', 'S5_PGDIR'), ('VP_DST_TSAP', 'Eop')
              ])
        self.params.credit = pkt.pdutype & 0x0f
        self._send_and_log(pkt)

    def _is_right_cc(self, pkt):
        if COTP_CC in pkt and pkt.dst == self.params.conn.smac:
            self._report_pkt(pkt, recv=1)
            self.params.conn.dref = pkt.sref
            return True
        return False

    def _send_cc_ak(self):
        pkt = self._l2_packet() / \
              COTP(pdu_name='AK_TPDU', dref=self.params.conn.dref,
                   tpdunr=self.params.your_tpdunr, credit=self.params.credit)
        self._send_and_log(pkt)

    def _recv_cr(self, pkt):
        if COTP_CR in pkt:
            self._report_pkt(pkt, recv=1)
            self.params.conn.dmac = pkt.src
            self.params.conn.dref = pkt.sref
            return True
        return False

    def _send_cc(self):
        pkt = self._l2_packet() / \
              COTP(pdu_name='CC_TPDU', dref=self.params.conn.dref, sref=self.params.conn.sref,
                   params=['VP_TPDU_SIZE', 'VP_OPT_SEL'])
        self.params.credit = pkt.pdutype & 0x0f
        self._send_and_log(pkt)

    def _is_right_cc_ak(self, pkt):
        conn = self.params.conn
        if COTP_AK in pkt and \
                conn.dmac == pkt.src and \
                conn.smac == pkt.dst and \
                conn.sref == pkt.dref:
            self._report_pkt(pkt, recv=1)
            self.params.my_tpdunr = pkt.tpdunr
            return True
        return False

    def _set_timeout_errno(self):
        self.errno = 200


# COTP接收数据包自动机
class COTP_ATMT_Receive(COTP_ATMT_Baseclass):
    def construct(self):
        self.trans = [
            (s('RECV_BEGIN', initial=1) >> s('RECEIVING')),
            (s('RECEIVING') >> s('END', final=1)) + cond(self._recv_pkt, recv_pkt=1) + action(self._disconnected)
        ]

    def parse_args(self, **kwargs):
        self._recv_callback = kwargs.pop('recv_callback', None)
        self._close_callback = kwargs.pop('close_callback', None)
        COTP_ATMT_Baseclass.parse_args(self, **kwargs)

    def _recv_pkt(self, pkt):
        self._report_pkt(pkt, recv=1)
        if self._is_bound_to_this_connection(pkt):
            if COTP_DT in pkt:
                self._recv_dt(pkt)
            if COTP_DR in pkt:
                self._recv_dr(pkt)
                return True
        return False

    def _recv_dt(self, pkt):
        dt_pkt = dissect_cotp(pkt.original)
        payload = dt_pkt.getlayer(Raw).load
        log.debug('负载：{}'.format(payload))
        self._send_ak()
        self._recv_callback(payload)

    def _send_ak(self):
        self.params.your_tpdunr += 1
        pkt = self._l2_packet() / \
              COTP(pdu_name='AK_TPDU', dref=self.params.conn.dref,
                   tpdunr=self.params.your_tpdunr, credit=self.params.credit)
        self._send_and_log(pkt)

    def _recv_dr(self, pkt):
        log.debug("cause: {}".format(COTP_CAUSE.get(pkt.cause, COTP_CAUSE[0])))
        self._send_dc()

    def _send_dc(self):
        pkt = self._l2_packet() / \
              COTP(pdu_name='DC_TPDU', dref=self.params.conn.dref, sref=self.params.conn.sref)
        self._send_and_log(pkt)

    def _disconnected(self):
        self._close_callback()


# COTP发送数据包自动机
class COTP_ATMT_Send(COTP_ATMT_Baseclass):
    def construct(self):
        self.trans = [
            (s('SEND_BEGIN', initial=1) >> s('WAIT_FOR_DT_AK')) + action(self._send_dt),
            (s('WAIT_FOR_DT_AK') >> s('END', final=1)) + cond(self._recv_ak, recv_pkt=1)
        ]

    def parse_args(self, **kwargs):
        self.data = kwargs.pop('data', b'')
        COTP_ATMT_Baseclass.parse_args(self, **kwargs)

    def _send_dt(self):
        pkt = self._l2_packet() / \
              COTP(pdu_name='DT_TPDU', dref=self.params.conn.dref, tpdunr=self.params.my_tpdunr) / \
              self.data
        self._send_and_log(pkt)

    def _recv_ak(self, pkt):
        if COTP_AK in pkt and self._is_bound_to_this_connection(pkt):
            self._report_pkt(pkt, recv=1)
            self.params.my_tpdunr = pkt.tpdunr
            return True
        return False


# COTP拆接自动机
class COTP_ATMT_Disconnect(COTP_ATMT_Baseclass):
    def construct(self):
        self.trans = [
            (s('CLOSE_BEGIN', initial=1) >> s('WAIT_FOR_DC')) + action(self._send_dr),
            (s('WAIT_FOR_DC') >> s('END', final=1)) + cond(self._recv_dc, recv_pkt=1),
            (s('WAIT_FOR_DC') >> s('END', final=1)) + cond(timeout=COTP_TIMEOUT)
        ]

    def _send_dr(self):
        pkt = self._l2_packet() / \
              COTP(pdu_name='DR_TPDU', dref=self.params.conn.dref, sref=self.params.conn.sref,
                   cause=self.params.cause)
        self._send_and_log(pkt)

    def _recv_dc(self, pkt):
        if COTP_DC in pkt and self._is_bound_to_this_connection(pkt):
            return True
        return False
