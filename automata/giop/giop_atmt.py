from scapy.layers.inet import *
from protocols.packet_giop import *
from utils.base_automaton import *
from config import *
from socket import *

SRC_IP = ''


class GIOPATMTBase(BaseAutomaton):
    def __init__(self, *args, **kwargs):
        BaseAutomaton.__init__(self, ll=conf.L3socket, *args, **kwargs)
        self.errno = 0
        self.params = None  # GIOPConfig

    # 用法： Automaton初始化时会调用此函数, 以更新参数
    def parse_args(self, **kwargs):
        log.debug("GIOP初始化参数...")
        self.params = kwargs.pop('params', None)
        log.info("网络接口: " + self.params.iface)
        BaseAutomaton.parse_args(self, debug=0, iface=self.params.iface, **kwargs)  # 根据本机环境修改 iface

    # 用法： Automaton进入recveive_condition后, 收到 pkt 时, 会调用此函数, 作为全局数据包过滤
    def master_filter(self, pkt):
        return TCP in pkt


class GIOPRequestATMT(GIOPATMTBase):
    def __init__(self):
        GIOPATMTBase.__init__(self)
        self.request_id = None

    def construct(self):
        self.trans = [
            (s('BEGIN', initial=1) >> s('WAIT_REPLY_DIC_READ_INT_INFO_TAG')) +
            cond(self.tcp_connect) + action(self.send_idl_dic_read_int_info_tag),
            (s('WAIT_REPLY_DIC_READ_INT_INFO_TAG') >> s('WAIT_REPLY_DIC_READ_INT_INFO_TAG_2')) +
            cond(self.recv_reply1, recv_pkt=1) + action(self.send_idl_dic_read_int_info_tag_2),
            (s('WAIT_REPLY_DIC_READ_INT_INFO_TAG_2') >> s('WAIT_REPLY_DIC_DB_SUBSCRIBE')) +
            cond(self.recv_reply1, recv_pkt=1) + action(self.send_idl_db_subsribe),

            # 建立TCP连接
            # 发送 idl_dic_read_int_info_tag
            #     收到 reply
            # 发送 idl_db_subscribe
            #     收到 reply
        ]

    def tcp_connect(self):
        skt = socket(socket.AF_INET, socket.SOCK_STREAM)
        skt.connect(('192.168.69.111', 10000))
        return True

    def send_idl_dic_read_int_info_tag(self):
        # 封装数据包
        pkt = IP(src='192.168.69.201', dst='192.168.69.111') / TCP(dport=10000) / \
              GIOP(type='Request',
                   RequestID=27090,
                   KeyAddress=h2b('14010f00525354b0942b5f771f0600060000000100000007000000'),
                   RequestOperation='idl_dic_read_int_info_tag',
                   StubData=h2b('0800434441502020202020202020202020'))
        self.send(pkt)
        self.request_id = pkt.GIOPFixedPart.RequestID  # 取得request_id

    def recv_reply1(self, pkt):
        # MAC/IP/TCP/PAYLOAD
        # 解析为GIOP数据包
        p = GIOP_Reply(pkt.load)
        # p: GIOP_Reply
        # 看 type 是不是 reply 的 type
        # 不是reply就忽略
        if p.GIOPFixedPart.GIOPHeader.MessageType == 0x01:
            # 这是一个reply包
            pkt.remove_payload()  # 移除掉pkt里面的payload
            # pkt: MAC/IP/TCP

            # 把已经解析的 giop层，续在 pkt 后面
            pkt = pkt / p
            # pkt: MAC/IP/TCP/GIOP_REPLY

            request_id = pkt.GIOPFixedPart.RequestID
            if request_id == self.request_id:
                return True
        return False

    def send_idl_dic_read_int_info_tag_2(self):
        pkt = IP(src='192.168.69.201', dst='192.168.69.111') / TCP(dport=10000) / \
              GIOP(type='Request', 
                   RequestID=27091,
                   KeyAddress=h2b('14010f00525354b0942b5f771f0600060000000100000007000000'),
                   RequestOperation='idl_dic_read_int_info_tag',
                   StubData=h2b('0800434452502020202020202020202020'))
        self.send(pkt)
        self.request_id = pkt.GIOPFixedPart.RequestID



