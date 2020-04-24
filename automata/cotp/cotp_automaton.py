from scapy.automaton import *
from scapy.layers.inet import *
from scapy.data import *
from scapy.utils import *
from protocols.cotp import *
from automata.cotp.cotp_config import *
from config import log


class COTP_ATMT_Baseclass(Automaton):
    # __init__不是 Automaton 的典型初始化函数， 使用 parse_args 代替
    def __init__(self, *args, **kwargs):
        Automaton.__init__(self, ll=conf.L2socket, *args, **kwargs)  # 需要使用 L2pcapSocket

    # 用法： 参考scapy文档 4.2.4
    def parse_args(self, **kwargs):
        Automaton.parse_args(self, debug=0, **kwargs)  # 根据本地环境修改 iface

    # 用法： 参考scapy文档 4.2.4
    def master_filter(self, pkt):
        return COTP_Base in pkt and pkt.src != self.smac

    # 日志函数
    def _report_transition(self, f):
        log.debug('状态转移：{}'.format(f.atmt_state))

    # 构造2层数据包
    def _l2_packet(self):
        return (Dot3(dst=self.dmac, src=self.smac) /
                LLC(dsap=0xfe, ssap=0xfe, ctrl=0x03) /
                CLNP())

    # 收到的 pkt 是否属于当前 cotp 连接
    def _is_bound_to_this_connection(self, pkt):
        conn1 = COTP_Connection(self.dmac, self.smac, self.dref, self.sref)
        conn2 = COTP_Connection(pkt.src, pkt.dst, pkt.sref, pkt.dref)
        return conn1 == conn2


class COTP_Automaton(COTP_ATMT_Baseclass):
    def __init__(self, *args, **kwargs):
        COTP_ATMT_Baseclass.__init__(self, *args, **kwargs)
        self.your_tpdunr = 0
        self.my_tpdunr = 0
        self.credit = 0
        self.errno = 0
        self.is_connected = False
        self.is_closing = False
        self._callback_connected = None
        self._callback_disconnected = None
        self._callback_error = None
        self._callback_recv = None
        self._disconnect_atmt = None

    # 用法： 参考scapy文档 4.2.4
    def parse_args(self, **kwargs):
        log.debug("初始化参数...")
        self.iface = kwargs.pop('iface', '')
        self.is_server = kwargs.pop('is_server', False)
        self.dmac = kwargs.pop('dmac', '00:00:00:00:00:00')
        self.smac = kwargs.pop('smac', '00:00:00:00:00:00')
        self.dref = kwargs.pop('dref', 0x0000)
        self.sref = kwargs.pop('sref', 0x0000)
        COTP_ATMT_Baseclass.parse_args(self, iface=self.iface, **kwargs)  # 根据本地环境修改 iface

    # 发送数据，阻塞式接口
    def send_bytes(self, buf):
        if not self.is_connected:
            log.warning('DT-TPDU 发送错误：连接未建立')
            return
        send_job = COTP_Send(dmac=self.dmac, smac=self.smac, dref=self.dref, my_tpdunr=self.my_tpdunr,
                             credit=self.credit, iface=self.iface, data=buf)
        send_job.run()
        self.my_tpdunr = send_job.my_tpdunr

    def disconnect(self):
        if not self.is_connected:
            return
        if self._disconnect_atmt is None:
            self._disconnect_atmt = COTP_Disconnect(callback_disconnected=self._callback_disconnected,
                                                    dmac=self.dmac, smac=self.smac, dref=self.dref, sref=self.sref,
                                                    credit=self.credit, cause=0x80, iface=self.iface)
        self._disconnect_atmt.runbg()
        self.is_closing = True

    # 注册回调
    def regist_callbacks(self,
                         callback_connected=None,
                         callback_disconnected=None,
                         callback_error=None,
                         callback_recv=None):
        self._callback_connected = callback_connected
        self._callback_disconnected = callback_disconnected
        self._callback_error = callback_error
        self._callback_recv = callback_recv

    # 状态： 初始状态
    @ATMT.state(initial=1)
    def BEGIN(self):
        self._report_transition(self.BEGIN)
        print(dir(self))
        # 验证参数
        if self.sref == 0x00:
            self.errno = 103
            log.warning('非法的本机ref：sref == 0x00')
            raise self.ERROR_PARAM()
        if not is_mac(self.dmac):
            self.errno = 100
            log.warning('非法的目标mac：dmac == {}'.format(self.dmac))
            raise self.ERROR_PARAM()
        if not is_mac(self.smac):
            self.errno = 101
            log.warning('非法的本机mac：smac == {}'.format(self.smac))
            raise self.ERROR_PARAM()
        raise self.CONNECTION_CLOSE()

    # 状态： 连接关闭
    @ATMT.state()
    def CONNECTION_CLOSE(self):
        self._report_transition(self.CONNECTION_CLOSE)
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
        cc = self._l2_packet() / \
             COTP(pdu_name='CC_TPDU', dref=self.dref, sref=self.sref,
                  params=['VP_TPDU_SIZE', 'VP_OPT_SEL'])
        self.credit = cc.pdutype & 0x0f
        self.send(cc)
        log.debug("发送 CC-TPDU：{}".format(hexstr(cc, onlyhex=1)))

    # 状态： 等待 CC 的 AK-TPDU
    @ATMT.state()
    def WAIT_FOR_CC_AK(self):
        self._report_transition(self.WAIT_FOR_CC_AK)
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
        cr = self._l2_packet() / \
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
        self._report_transition(self.WAIT_FOR_CC)
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
        ak = self._l2_packet() / COTP(pdu_name='AK_TPDU', dref=self.dref,
                                     tpdunr=self.your_tpdunr, credit=self.credit)
        self.send(ak)
        log.debug("发送 CC 的 AK-TPDU：{}".format(hexstr(ak, onlyhex=1)))

    # 转移事件： 等待 CC 超时
    @ATMT.timeout(WAIT_FOR_CC, COTP_TIMEOUT)
    def waiting_timeout_cc(self):
        raise self.ERROR_TIMEOUT()

    # 转移事件： 等待 CC-AK 超时
    @ATMT.timeout(WAIT_FOR_CC_AK, COTP_TIMEOUT)
    def waiting_timeout_cc_ak(self):
        raise self.ERROR_TIMEOUT()

    # 状态： 连接打开
    @ATMT.state()
    def CONNECTION_OPEN(self):
        self._report_transition(self.CONNECTION_OPEN)
        self.is_connected = True
        self._callback_connected()
        log.debug('连接已建立')
        log.debug('等待数据包...')

    # 转移事件： 接收数据包
    @ATMT.receive_condition(CONNECTION_OPEN)
    def listening(self, pkt):
        if self.is_closing:
            # 当拆接自动机以超时方式断开连接后，此分支有可能无法进入，导致主自动机无法结束
            # TODO: 寻找改进方法
            raise self.END()
        if COTP_DT in pkt:
            self._recv_dt(pkt)
        elif COTP_CR in pkt:
            self._recv_cr(pkt)
        elif COTP_AK in pkt:
            pass  # AK-TPDU 在 COTP_Send 中处理
        elif COTP_DR in pkt:
            if self._is_bound_to_this_connection(pkt):
                self._recv_dr(pkt)
                self._callback_disconnected()
                raise self.END()
        else:
            log.debug('收到忽略的数据包：{}'.format(hexstr(pkt, onlyhex=1)))

    # 状态： 超时错误
    @ATMT.state(error=1)
    def ERROR_TIMEOUT(self):
        self._report_transition(self.ERROR_TIMEOUT)
        raise self.END()

    # 状态： 发送错误
    @ATMT.state(error=1)
    def ERROR_SEND(self):
        self._report_transition(self.ERROR_SEND)
        raise self.END()

    # 状态： 参数错误
    @ATMT.state(error=1)
    def ERROR_PARAM(self):
        self._report_transition(self.ERROR_PARAM)
        raise self.END()

    # 状态： 结束
    @ATMT.state(final=1)
    def END(self):
        self._report_transition(self.END)
        if self.errno > 0:
            self._callback_error(self.errno)

    # 收到 DT-TPDU
    def _recv_dt(self, pkt):
        payload = str(pkt.getlayer(Raw).load, encoding="utf-8").replace('\x00', '')
        log.debug('收到 DT-TPDU：{}'.format(hexstr(pkt, onlyhex=1)))
        log.debug('负载：{}'.format(payload))
        self._callback_recv(payload)
        # 返回 AK-TPDU
        self.your_tpdunr += 1
        ak = self._l2_packet() / COTP(pdu_name='AK_TPDU', dref=self.dref,
                                     tpdunr=self.your_tpdunr, credit=self.credit)
        self.send(ak)
        log.debug("发送 AK-TPDU：{}".format(hexstr(ak, onlyhex=1)))

    # 收到 CR-TPDU，对于已建立的连接，返回 CC
    def _recv_cr(self, pkt):
        log.debug('收到 CR-TPDU：{}'.format(hexstr(pkt, onlyhex=1)))
        if pkt.sref == self.dref and pkt.dst == self.smac and pkt.src == self.dmac:
            self.send_cc()

    # 收到 DR-TPDU
    def _recv_dr(self, pkt):
        log.debug("收到 DR-TPDU：{}".format(hexstr(pkt, onlyhex=1)))
        log.debug("cause: {}".format(COTP_CAUSE.get(pkt.cause, COTP_CAUSE[0])))
        dc = self._l2_packet() / \
             COTP(pdu_name='DC_TPDU', dref=self.dref, sref=self.sref)
        self.send(dc)
        log.debug("发送 DC-TPDU：{}".format(hexstr(dc, onlyhex=1)))


# COTP发送数据包自动机
class COTP_Send(COTP_ATMT_Baseclass):
    def __init__(self, *args, **kwargs):
        COTP_ATMT_Baseclass.__init__(self, *args, **kwargs)
        self.errno = 0

    # 用法： 参考scapy文档 4.2.4
    def parse_args(self, **kwargs):
        self.iface = kwargs.pop('iface', '')
        self.dmac = kwargs.pop('dmac', '00:00:00:00:00:00')
        self.smac = kwargs.pop('smac', '00:00:00:00:00:00')
        self.dref = kwargs.pop('dref', 0x0000)
        self.my_tpdunr = kwargs.pop('my_tpdunr', 0)
        self.credit = kwargs.pop('credit', 0)
        self.data = kwargs.pop('data', b'')
        COTP_ATMT_Baseclass.parse_args(self, iface=self.iface, **kwargs)  # 根据本地环境修改 iface

    # 状态： 发送 DT-TPDU
    @ATMT.state(initial=1)
    def WORK(self):
        self._send_dt()
        raise self.WAIT_FOR_DT_AK()

    # TODO: 可添加超时重传
    # 状态： 等待 DT-TPDU 的 AK
    @ATMT.state()
    def WAIT_FOR_DT_AK(self):
        pass

    # 转移事件： 等待 DT-TPDU 的 AK
    @ATMT.receive_condition(WAIT_FOR_DT_AK)
    def waiting_for_dt_ak(self, pkt):
        if COTP_AK in pkt:
            self._recv_ak(pkt)
            raise self.END()
        else:
            log.debug('收到忽略的数据包：{}'.format(hexstr(pkt, onlyhex=1)))

    # 状态： 结束
    @ATMT.state(final=1)
    def END(self):
        pass

    # 发送 DT-TPDU
    def _send_dt(self):
        dt = self._l2_packet() / \
             COTP(pdu_name='DT_TPDU', dref=self.dref, tpdunr=self.my_tpdunr) / \
             self.data
        self.send(dt)
        log.debug("发送 DT-TPDU：{}".format(hexstr(dt, onlyhex=1)))

    # 收到 AK-TPDU
    def _recv_ak(self, pkt):
        log.debug('收到 AK-TPDU：{}'.format(hexstr(pkt, onlyhex=1)))
        self.my_tpdunr = pkt.tpdunr


# COTP拆接自动机
class COTP_Disconnect(COTP_ATMT_Baseclass):
    def __init__(self, callback_disconnected, *args, **kwargs):
        COTP_ATMT_Baseclass.__init__(self, *args, **kwargs)
        self.errno = 0
        self._callback_disconnected = callback_disconnected

    # 用法： 参考scapy文档 4.2.4
    def parse_args(self, **kwargs):
        self.iface = kwargs.pop('iface', '')
        self.dmac = kwargs.pop('dmac', '00:00:00:00:00:00')
        self.smac = kwargs.pop('smac', '00:00:00:00:00:00')
        self.dref = kwargs.pop('dref', 0x0000)
        self.sref = kwargs.pop('sref', 0x0000)
        self.credit = kwargs.pop('credit', 0)
        self.cause = kwargs.pop('cause', 0)
        COTP_ATMT_Baseclass.parse_args(self, iface=self.iface, **kwargs)

    # 状态： 初始状态，发送 DR-TPDU
    @ATMT.state(initial=1)
    def BEGIN(self):
        self._send_dr()
        raise self.WAIT_FOR_DC()

    # 状态： 等待 DC-TPDU
    @ATMT.state()
    def WAIT_FOR_DC(self):
        pass

    # 转移事件： 等待 DC-TPDU
    @ATMT.receive_condition(WAIT_FOR_DC)
    def waiting_for_dc(self, pkt):
        if COTP_DC in pkt:
            log.debug("收到 DC-TPDU：{}".format(hexstr(pkt, onlyhex=1)))
            if self._is_bound_to_this_connection(pkt):
                raise self.END()
        elif COTP_DR in pkt:
            log.debug("收到 DR-TPDU：{}".format(hexstr(pkt, onlyhex=1)))
            log.debug("cause: {}".format(COTP_CAUSE.get(pkt.cause, COTP_CAUSE[0])))
            if self._is_bound_to_this_connection(pkt):
                raise self.END()
        else:
            log.debug('拆接期间收到忽略的数据包：{}'.format(hexstr(pkt, onlyhex=1)))

    # 转移事件： 等待超时
    @ATMT.timeout(WAIT_FOR_DC, COTP_TIMEOUT)
    def waiting_timeout_dc(self):
        raise self.END()

    # 状态： 结束
    @ATMT.state(final=1)
    def END(self):
        self._callback_disconnected()
        log.debug('连接已断开')
        pass

    def _send_dr(self):
        dr = self._l2_packet() / \
             COTP(pdu_name='DR_TPDU', dref=self.dref, sref=self.sref, credit=self.credit, cause=self.cause)
        self.send(dr)
        log.debug("发送 DR-TPDU：{}".format(hexstr(dr, onlyhex=1)))

