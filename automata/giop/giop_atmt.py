from scapy.layers.inet import *
from protocols.packet_giop import *
from utils.base_automaton import *
from config import *
from socket import *
import time

TEST_HOST = '54:BF:64:0C:B4:B6'
TEST_IP = '169.254.58.190'
SRC_MAC = '80:e8:2c:cb:43:4f'
DST_MAC = '94:18:82:7c:9e:14'
SRC_IP = '192.168.69.201'  # OWP1
DST_IP = '192.168.69.111'  # SAR1/STR1


class RealtimeConfigGetter(BaseAutomaton):
    TIMESTAMP = 0
    IP_ID = 0

    def parse_args(self, **kwargs):
        self.iface = kwargs.pop('iface', '')
        log.info("TimestampGetter网络接口: " + self.iface)
        BaseAutomaton.parse_args(self, debug=0, iface=self.iface, **kwargs)

    def master_filter(self, pkt):
        return TCP in pkt and pkt[IP].src == '192.168.69.201'

    def construct(self):
        self.trans = [
            (s('BEGIN', initial=1) >> s('RECV_PKT')) + cond(self.recv_pkt, recv_pkt=1, need_log=0),
            (s('RECV_PKT') >> s('END', final=1))
        ]

    def recv_pkt(self, pkt):
        opts = pkt[TCP].options
        for opt in opts:
            if opt[0] == 'Timestamp':
                RealtimeConfigGetter.TIMESTAMP = opt[1][0]
        if pkt[TCP].sport == 49916:
            RealtimeConfigGetter.IP_ID = pkt[IP].id
            # print(RealtimeConfigGetter.IP_ID)
        return False


class GIOPATMTBase(BaseAutomaton):
    def __init__(self, *args, **kwargs):
        BaseAutomaton.__init__(self, ll=conf.L2socket, *args, **kwargs)
        self.errno = 0

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
    def __init__(self, *args, **kwargs):
        GIOPATMTBase.__init__(self, *args, **kwargs)
        self.request_id = 30000
        self.skt = None

    def construct(self):
        self.trans = [
            (s('BEGIN', initial=1) >> s('WAIT_REPLY_DIC_READ_INT_INFO_TAG')) +
            cond(self.tcp_connect) + action(self.send_idl_db_locked_multiple_write)
        ]
        ''',
            (s('WAIT_REPLY_DIC_READ_INT_INFO_TAG') >> s('WAIT_REPLY_DIC_READ_INT_INFO_TAG_2')) +
            cond(self.recv_reply('corresponding_requestID_is_27090'), recv_pkt=0) +
            action(self.send_idl_dic_read_int_info_tag_2),
            (s('WAIT_REPLY_DIC_READ_INT_INFO_TAG_2') >> s('WAIT_REPLY_DB_SUBSCRIBE')) +
            cond(self.recv_reply('corresponding_requestID_is_27091'), recv_pkt=0) +
            action(self.send_idl_db_subsribe),
            (s('WAIT_REPLY_DB_SUBSCRIBE') >> s('WAIT_REPLY_DB_SUBSCRIBE_2')) +
            cond(self.recv_reply('corresponding_requestID_is_27092'), recv_pkt=0) +
            action(self.send_idl_db_subsribe_2),
            (s('WAIT_REPLY_DB_SUBSCRIBE_2') >> s('WAIT_REPLY_DB_LOCKED_MULTIPLE_WRITE')) +
            cond(self.recv_reply('corresponding_requestID_is_27093'), recv_pkt=0) +
            action(self.send_idl_db_locked_multiple_write),
            (s('WAIT_REPLY_DB_LOCKED_MULTIPLE_WRITE') >> s('WAIT_REPLY_DB_UNSUBSCRIBE')) +
            cond(self.recv_reply('corresponding_requestID_is_27094'), recv_pkt=0) +
            action(self.send_idl_db_unsubscribe),
            (s('WAIT_REPLY_DB_UNSUBSCRIBE') >> s('WAIT_REPLY_DB_UNSUBSCRIBE_2')) +
            cond(self.recv_reply('corresponding_requestID_is_27095'), recv_pkt=0) +
            action(self.send_idl_db_unsubscribe_2),
            (s('WAIT_REPLY_DB_UNSUBSCRIBE_2') >> s('END', final=1))
        ]
        '''

    # 建立TCP连接
    # 发送 idl_dic_read_int_info_tag
    #     收到 reply
    # 发送 idl_db_subscribe
    #     收到 reply
    def tcp_connect(self):
        self.skt = socket(AF_INET, SOCK_STREAM)
        self.skt.connect(('192.168.69.111', 10000))
        return True

    def recv_reply(self, func_name):
        def recv_reply1(pkt=None):
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

        recv_reply1.__name__ = func_name
        return recv_reply1

    def send_idl_dic_read_int_info_tag(self):
        # 封装数据包
        self.request_id = self.request_id + 1
        pkt = GIOP(type='Request',
                   RequestID=self.request_id,
                   KeyAddress=h2b('14010f00525354f39d825f66c00300060000000100000007000000'),
                   RequestOperation='idl_dic_read_int_info_tag',
                   StubData=h2b('1e00434441502020202020202020202020'))
        self.skt.send(bytes(pkt))
        self.request_id = pkt.GIOPFixedPart.RequestID  # 取得request_id
        time.sleep(10000)

    def send_idl_dic_read_int_info_tag_2(self):
        self.request_id = self.request_id + 1
        pkt = GIOP(type='Request',
                   RequestID=self.request_id,
                   KeyAddress=h2b('14010f00525354b0942b5f771f0600060000000100000007000000'),
                   RequestOperation='idl_dic_read_int_info_tag',
                   StubData=h2b('0800434452502020202020202020202020'))
        self.skt.send(bytes(pkt))
        self.request_id = pkt.GIOPFixedPart.RequestID

    def send_idl_db_subsribe(self):
        self.request_id = self.request_id + 1
        pkt = GIOP(type='Request',
                   RequestID=self.request_id,
                   KeyAddress=h2b('14010f00525354b0942b5f771f0600040000000100000005000000'),
                   RequestOperation='idl_db_subscribe',
                   StubData=h2b('36000000010000000e0000000800c00000041e00080000000000'))
        self.skt.send(bytes(pkt))
        self.request_id = pkt.GIOPFixedPart.RequestID

    def send_idl_db_subsribe_2(self):
        self.request_id = self.request_id + 1
        pkt = GIOP(type='Request',
                   RequestID=self.request_id,
                   KeyAddress=h2b('14010f00525354b0942b5f771f0600040000000100000005000000'),
                   RequestOperation='idl_db_subscribe',
                   StubData=h2b('36000000010000000e0000000800c00000041d00080000000000'))
        self.skt.send(bytes(pkt))
        self.request_id = pkt.GIOPFixedPart.RequestID  # 取得request_id

    def send_idl_db_locked_multiple_write(self):
        self.request_id = self.request_id + 1
        pkt = GIOP(type='Request',
                   RequestID=self.request_id,
                   KeyAddress=h2b('14010f00525354f39d825f66c00300040000000100000005000000'),
                   RequestOperation='idl_db_locked_multiple_write',
                   StubData=h2b(
                       '0000000000000000000000001b0000001e00370001049c010200012e000000000000000600000000000000'))
        #               1 2 3 4 5 6 7 8 9 10  12  14  16  18  20  22  24  26  28  30  32  34  36  38  40  42
        #                                   11  13  15  17  19  21  23  25  27  29  31  33  35  37  39  41  43
        self.skt.send(bytes(pkt))
        self.request_id = pkt.GIOPFixedPart.RequestID  # 取得request_id

        return
        print('Sleeping... 200ms')
        time.sleep(0.2)

        # 改值的multiple-write可以没有第二个write
        self.request_id = self.request_id + 1
        pkt = GIOP(type='Request',
                   RequestID=self.request_id,
                   KeyAddress=h2b('14010f00525354f39d825f66c00300040000000100000005000000'),
                   RequestOperation='idl_db_locked_multiple_write',
                   StubData=h2b(
                       '6d00000003702960287902001b0000001e00370001049e0104000118000000010000000700000000000000'))
        self.skt.send(bytes(pkt))
        self.request_id = pkt.GIOPFixedPart.RequestID  # 取得request_id

    def send_idl_db_unsubscribe(self):
        self.request_id = self.request_id + 1
        pkt = GIOP(type='Request',
                   RequestID=self.request_id,
                   KeyAddress=h2b('14010f00525354b0942b5f771f0600040000000100000005000000'),
                   RequestOperation='idl_db_unsubscribe',
                   StubData=h2b('36000000000000000e0000000800c00000041d0008000000000001'))
        self.skt.send(bytes(pkt))
        self.request_id = pkt.GIOPFixedPart.RequestID  # 取得request_id

    def send_idl_db_unsubscribe_2(self):
        self.request_id = self.request_id + 1
        pkt = GIOP(type='Request',
                   RequestID=self.request_id,
                   KeyAddress=h2b('14010f00525354b0942b5f771f0600040000000100000005000000'),
                   RequestOperation='idl_db_unsubscribe',
                   StubData=h2b('36000000000000000e0000000800c00000041e0008000000000001'))
        self.skt.send(bytes(pkt))
        self.request_id = pkt.GIOPFixedPart.RequestID  # 取得request_id
