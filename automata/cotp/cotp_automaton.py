from scapy.automaton import *
from scapy.layers.inet import *
from scapy.data import *
from scapy.utils import *
from protocols.cotp import *
from automata.cotp.cotp_config import cotp_conf
import logging as log


class COTP_Automaton(Automaton):
    timeout = 15  # 单位： 秒

    # __init__不是 Automaton 的典型初始化函数， 使用 parse_args 代替
    def __init__(self, *args, **kwargs):
        Automaton.__init__(self, ll=conf.L2socket, *args, **kwargs)  # 需要使用 L2pcapSocket

    # 用法： 参考scapy文档 4.2.4
    def parse_args(self, **kwargs):
        log.debug("初始化参数...")
        self.iface = kwargs.pop('iface', 'Killer E2400 Gigabit Ethernet Controller #2')
        self.is_server = kwargs.pop('is_server', False)
        self.dmac = kwargs.pop('dmac', '00:00:00:00:00:00')
        self.smac = kwargs.pop('smac', '00:00:00:00:00:00')
        self.dref = kwargs.pop('dref', 0x0000)
        self.sref = kwargs.pop('sref', 0x0000)
        self.your_tpdunr = 0
        self.my_tpdunr = 0
        self.credit = 0
        Automaton.parse_args(self, iface=self.iface, **kwargs)  # 根据本地环境修改 iface

    # 用法： 参考scapy文档 4.2.4
    def master_filter(self, pkt):
        return COTP_Base in pkt and pkt.src != self.smac

    def send_bytes(self, buf):
        if self.state.state != self.CONNECTION_OPEN.atmt_state:
            log.warning('DT-TPDU 发送错误：连接未建立')
            return
        dt = self.l2_packet() / \
             COTP(pdu_name='DT_TPDU', dref=self.dref, tpdunr=self.my_tpdunr) / \
             buf
        self.send(dt)
        log.debug("发送 DT-TPDU：{}".format(hexstr(dt, onlyhex=1)))

    # 状态： 初始状态
    @ATMT.state(initial=1)
    def BEGIN(self):
        self.report_transition(self.BEGIN)
        if self.sref == 0x00:
            log.warning('非法的本机ref：sref == 0x00')
            raise self.END()
        raise self.CONNECTION_CLOSE()

    # 状态： 连接关闭
    @ATMT.state()
    def CONNECTION_CLOSE(self):
        self.report_transition(self.CONNECTION_CLOSE)
        pass

    # 转移事件： 是客户端
    @ATMT.condition(CONNECTION_CLOSE, prio=0)
    def it_is_client(self):
        if not self.is_server:
            log.debug("转移事件：客户端")
            raise self.WAIT_FOR_CC()

    # 转移事件： 是服务端
    @ATMT.condition(CONNECTION_CLOSE, prio=1)
    def it_is_server(self):
        log.debug("转移事件：服务端")
        log.debug('等待 CR-TPDU ...')

    # 转移事件： 等待 CR-TPDU
    @ATMT.receive_condition(it_is_server)
    def listen_for_cr(self, pkt):
        if COTP_CR in pkt:
            log.debug('收到 CR-TPDU：{}'.format(hexstr(pkt, onlyhex=1)))
            self.dref = pkt.sref
            raise self.WAIT_FOR_CC_AK()

    # 行为： 发送 CC-TPDU
    @ATMT.action(listen_for_cr)
    def send_cc(self):
        cc = self.l2_packet() / \
             COTP(pdu_name='CC_TPDU', dref=self.dref, sref=self.sref,
                  params=['VP_TPDU_SIZE', 'VP_OPT_SEL'])
        self.credit = cc.pdutype & 0x0f
        self.send(cc)
        log.debug("发送 CC-TPDU：{}".format(hexstr(cc, onlyhex=1)))

    # 状态： 等待 CC 的 AK-TPDU
    @ATMT.state()
    def WAIT_FOR_CC_AK(self):
        self.report_transition(self.WAIT_FOR_CC_AK)
        pass

    # 转移事件： 等待 CC 的 AK-TPDU
    @ATMT.receive_condition(WAIT_FOR_CC_AK)
    def listen_for_cc_ak(self, pkt):
        if COTP_AK in pkt:
            log.debug('收到 CC 的 AK-TPDU：{}'.format(hexstr(pkt, onlyhex=1)))
            self.my_tpdunr = pkt.tpdunr
            raise self.CONNECTION_OPEN()

    # 行为： 发送 CR-TPDU
    @ATMT.action(it_is_client)
    def send_cr(self):
        cr = self.l2_packet() / \
              COTP(pdu_name='CR_TPDU', dref=self.dref, sref=self.sref, params=[
                  ('VP_CHECKSUM', 0x1234), 'VP_TPDU_SIZE', 'VP_VERSION_NR',
                  'VP_OPT_SEL', ('VP_SRC_TSAP', 'S5_PGDIR'), ('VP_DST_TSAP', 'Eop')
              ])
        self.credit = cr.pdutype & 0x0f
        self.send(cr)
        log.debug("发送 CR-TPDU：{}".format(hexstr(cr, onlyhex=1)))
        raise self.WAIT_FOR_CC()

    # 状态： 等待 CC-TPDU
    @ATMT.state()
    def WAIT_FOR_CC(self):
        self.report_transition(self.WAIT_FOR_CC)
        pass

    # 转移事件： 等待 CC-TPDU
    @ATMT.receive_condition(WAIT_FOR_CC)
    def listen_for_cc(self, pkt):
        if COTP_CC in pkt:
            log.debug('收到 CC-TPDU：{}'.format(hexstr(pkt, onlyhex=1)))
            self.dref = pkt.sref
            raise self.CONNECTION_OPEN()

    # 行为： 发送 CC 的 AK-TPDU
    @ATMT.action(listen_for_cc)
    def send_cc_ak(self):
        ak = self.l2_packet() / COTP(pdu_name='AK_TPDU', dref=self.dref,
                                     tpdunr=self.your_tpdunr, credit=self.credit)
        self.send(ak)
        log.debug("发送 CC 的 AK-TPDU：{}".format(hexstr(ak, onlyhex=1)))

    # 转移事件： 等待 CC 超时
    @ATMT.timeout(WAIT_FOR_CC, timeout)
    def waiting_timeout_cc(self):
        raise self.ERROR_TIMEOUT()

    # 转移事件： 等待 CC-AK 超时
    @ATMT.timeout(WAIT_FOR_CC_AK, timeout)
    def waiting_timeout_cc_ak(self):
        raise self.ERROR_TIMEOUT()

    # 状态： 连接打开
    @ATMT.state()
    def CONNECTION_OPEN(self):
        self.report_transition(self.CONNECTION_OPEN)
        log.debug('等待数据包...')
        pass

    # 转移事件： 接收数据包
    @ATMT.receive_condition(CONNECTION_OPEN)
    def listening(self, pkt):
        if COTP_AK in pkt:
            log.debug('收到 AK-TPDU：{}'.format(hexstr(pkt, onlyhex=1)))
            self.my_tpdunr = pkt.tpdunr
        elif COTP_DT in pkt:
            payload = str(pkt.getlayer(Raw).load, encoding="utf-8").replace('\x00', '')
            log.debug('收到 DT-TPDU：{}'.format(hexstr(pkt, onlyhex=1)))
            log.debug('负载：{}'.format(payload))
            # 返回 AK-TPDU
            self.your_tpdunr += 1
            ak = self.l2_packet() / COTP(pdu_name='AK_TPDU', dref=self.dref,
                                         tpdunr=self.your_tpdunr, credit=self.credit)
            self.send(ak)
            log.debug("发送 AK-TPDU：{}".format(hexstr(ak, onlyhex=1)))
        else:
            log.debug('收到忽略的数据包：{}'.format(hexstr(pkt, onlyhex=1)))

    # 状态： 超时错误
    @ATMT.state(error=1)
    def ERROR_TIMEOUT(self):
        self.report_transition(self.ERROR_TIMEOUT)
        raise self.END()

    # 状态： 发送错误
    @ATMT.state(error=1)
    def ERROR_SEND(self):
        self.report_transition(self.ERROR_SEND)

    # 状态： 参数错误
    @ATMT.state(error=1)
    def ERROR_PARAM(self):
        self.report_transition(self.ERROR_PARAM)

    # 状态： 结束
    @ATMT.state(final=1)
    def END(self):
        self.report_transition(self.END)

    # 日志函数
    def report_transition(self, f):
        log.debug('状态转移：{}'.format(f.atmt_state))

    def l2_packet(self):
        return (Dot3(dst=self.dmac, src=self.smac) /
                LLC(dsap=0xfe, ssap=0xfe, ctrl=0x03) /
                CLNP())
