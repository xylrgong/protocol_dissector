from typing import Optional, Any

from scapy.automaton import *
from scapy.utils import *
from utils.base_automaton import *
from protocols.cotp import *
from automata.cotp.cotp_config import *
from config import *
from protocols.h1 import *
from automata.cotp.cotp_socket import *
from automata.s5.S5_config import *
import binascii


# S5自动机的基类
class S5_ATMT_Baseclass(BaseAutomaton):
    def __init__(self, *args, **kwargs):
        BaseAutomaton.__init__(self, *args, **kwargs)
        self.nooferr = 0
        self.cotp_skt = None

    # 用法： Automaton初始化时会调用此函数, 以更新参数
    def parse_args(self, **kwargs):
        log.debug("初始化参数...")
        self.params = kwargs.pop('params', None)
        BaseAutomaton.parse_args(self, debug=0, **kwargs)  # 根据本机环境修改 iface

    # 用法： Automaton进入recveive_condition后, 收到 pkt 时, 会调用此函数, 作为全局数据包过滤
    def master_filter(self, pkt):
        return COTP_Base in pkt and pkt.src != self.params.conn.smac

    def _cotp_connected(self):
        self.cotp_skt = COTPSocket(dmac='08:00:06:1a:11:11', smac='00:30:6e:0c:87:4e', sref=0x01,
                                   iface='以太网')
        if self.cotp_skt.connect():
            return False
        return True

    def _cotp_disconnect(self):
        self.cotp_skt.disconnect()
        self.cotp_skt = None

    def verifyDWNR(self, pkt, dwnr):
        h1_pkt = dissect_h1_ex(*pkt)
        pkt_DWNR = int.from_bytes(h1_pkt.Address_within_memory_block, byteorder='big')
        log.debug('收到序列号：{}'.format(pkt_DWNR))
        return pkt_DWNR == dwnr

    def set_payload_ex(self, set_status, equip):
        payload_2052 = ''
        payload_5124 = ''
        # close
        payload_close = ''
        # open
        payload_open = ''
        # reset
        payload_reset = ''
        if str(equip) == 'aa101':
            print('ap:ap101 and equip:aa101')
            payload_2052 = '0402040e001f'
            payload_5124 = '040200000000103f1032000efc02'
            # close
            payload_close = '04027070040e80000000001f8100200f783f6ff48100783f69f48000783f6bf48000783f63f48000783f64f48000783f6af48000783f68f48100783f6ef46500'
            # open
            payload_open = '04027070040e80000000001f8100200f783f6ff48000783f69f48000783f6bf48000783f63f48000783f64f48000783f6af48100783f68f48100783f6ef46500'
            # reset
            payload_reset = '04027070040e80000000001f8100200f783f6ff48000783f69f48000783f6bf48000783f63f48000783f64f48000783f6af48000783f68f48100783f6ef46500'
        elif str(equip) == 'aa102':
            print('ap:ap101 and equip:aa102')
            payload_2052 = '04020410003a'
            payload_5124 = '040200000000103f1032000efc02'
            # close
            payload_close = '04027070041080000000003a81002064783f6f028100783f69028000783f68028100783f6e02783f3e04783f65003d4f2d0800e600136400000500020836640c783f3f04783f63003d4f2d0800e6001164000003000208346408783f3d04783f64003d4f2d0800e600126400000400020835640a6500'
            # open
            payload_open = '04027070041080000000003a81002064783f6f028000783f69028100783f68028100783f6e02783f3e04783f65003d4f2d0800e600136400000500020836640c783f3f04783f63003d4f2d0800e6001164000003000208346408783f3d04783f64003d4f2d0800e600126400000400020835640a6500'
            payload_reset = '04027070041080000000003a81002064783f6f028000783f69028000783f68028100783f6e02783f3e04783f65003d4f2d0800e600136400000500020836640c783f3f04783f63003d4f2d0800e6001164000003000208346408783f3d04783f64003d4f2d0800e600126400000400020835640a6500'
        elif str(equip) == 'aa103':
            print('ap:ap101 and equip:aa103')
            payload_2052 = '040204110034'
            payload_5124 = '040200000000103f1032000efc02'
            # close
            payload_close = '040270700411800000000034a000fc02b10a8000910a810a300205001c02f802200f783f68f6a100fc01b00a8100900a800a300211001c01f801783f69f68100783f6ef68100783f6ff6200a783f2f0c2064783f66003d4f2d0800e600146400000600020857640e6500'
            # open
            payload_open = '040270700411800000000034a100fc02b10a8100910a810a300205001c02f802200f783f68f6a000fc01b00a8000900a800a300211001c01f801783f69f68100783f6ef68100783f6ff6200a783f2f0c2064783f66003d4f2d0800e600146400000600020857640e6500'
            # reset
            payload_reset = '040270700411800000000034a000fc02b10a8000910a810a300205001c02f802200f783f68f6a000fc01b00a8000900a800a300211001c01f801783f69f68100783f6ef68100783f6ff6200a783f2f0c2064783f66003d4f2d0800e600146400000600020857640e6500'
        elif str(equip) == 'aa104':
            print('ap:ap101 and equip:aa104')
            payload_2052 = '040204130013'
            payload_5124 = '040200000000103f1032000efc02'
            # close
            payload_close = '04027070041380000000001381002064783f69108000783f68108100783f6e108100783f6f106500'
            # open
            payload_open = '04027070041380000000001380002064783f69108100783f68108100783f6e108100783f6f106500'
            # reset
            payload_reset = '04027070041380000000001380002064783f69108000783f68108100783f6e108100783f6f106500'
        else:
            print('undefined equip')
        # set close/open
        if (set_status == 'set_close'):
            payload_data = payload_close
        elif (set_status == 'set_open'):
            payload_data = payload_open
        elif (set_status == 'set_reset'):
            payload_data = payload_reset
        else:
            payload_data = ''
        return [payload_2052, payload_5124, payload_data]

    def _is_65283(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 65283)

    def _is_7684(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 7684)

    def _is_3(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 3)


    def _is_4611(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 4611)

    def _is_4099(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 4099)

    def _is_4355(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 4355)

    def _is_2307(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 2307)

    def _is_5124(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 5124)

    def _is_9475(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 9475)

    def _is_21252(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 21252)

    def _is_6148(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 6148)

    def _is_1028(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 1028)

    def _is_7428(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 7428)

    def _is_32771(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 32771)

    def _is_33027(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 33027)

    def is_7684(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 7684)

    def _is_6916(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 6916)

    def _is_0(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 0)


# S5建立动态连接自动机
class S5_ATMT_DConnect(S5_ATMT_Baseclass):
    def construct(self):
        self.trans = [
            # 客户端部分
            (s('BEGIN', initial=1) >> s('WAIT_FOR_COTP_CONNECT')) + cond(self._cotp_connected),
            (s('WAIT_FOR_COTP_CONNECT') >> s('WAIT_FOR_D_65283')) + action(self._send_21252),
            (s('WAIT_FOR_D_65283') >> s('WAIT_FOR_D_3')) + cond(self._is_65283) + action(self._send_6148),
            (s('WAIT_FOR_D_3') >> s('WAIT_FOR_D_4611')) + cond(self._is_3),
            (s('WAIT_FOR_D_4611') >> s('WAIT_FOR_D_UNKNOWN')) + cond(self._is_4611)
            + action(self._send_7428),
            (s('WAIT_FOR_D_UNKNOWN') >> s('WAIT_FOR_D_0')) + cond(self._is_unknown)
            + action(self._send_6916),
            (s('WAIT_FOR_D_0') >> s('WAIT_FOR_D_3_')) + cond(self._is_0),
            (s('WAIT_FOR_D_3_') >> s('WAIT_FOR_D_4611_')) + cond(self._is_3),
            (s('WAIT_FOR_D_4611_') >> s('D_CONNECTED', final=1)) + cond(self._is_4611) + action(self._report_status),
        ]

    def _send_21252(self):
        payload = hex_bytes('0402010204010401000202')
        pkt = H1(opcode_name='D_Connect', request_block=['DB', 0x02, 0x5304, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_6148(self):
        payload = hex_bytes('0402')
        pkt = H1(opcode_name='D_Connect', request_block=['DB', 0x02, 0x1804, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_7428(self):
        payload = hex_bytes('0402')
        pkt = H1(opcode_name='D_Connect', request_block=['DB', 0x02, 0x1d04, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _is_unknown(self):
        buf = self.cotp_skt.recv_data_block(1)
        hexPKTstr = str(binascii.b2a_hex(bytes(*buf, encoding="utf8")))
        hexopcode_str = hexPKTstr[12:14]
        if hexopcode_str == '8e':
            return True
        return False

    def _send_6916(self):
        payload = hex_bytes('040201')
        pkt = H1(opcode_name='D_Connect', request_block=['DB', 0x02, 0x1b04, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _report_status(self):
        log.debug("成功建立动态连接，等待指令...")


# s5阀门操作自动机
class S5_ATMT_OPERATE(S5_ATMT_Baseclass):
    def construct(self):
        self.trans = [
            # 客户端部分
            (s('BEGIN', initial=1) >> s('WAIT_FOR_4099')) + cond(lambda: self.cotp_skt.is_connected)
            + action(self._send_5124),
            (s('WAIT_FOR_4099') >> s('WAIT_FOR_3')) + cond(self._is_4099) + action(self._send_32771),
            (s('WAIT_FOR_3') >> s('WAIT_FOR_4355')) + cond(self._is_3) + action(self._send_33027),
            (s('WAIT_FOR_4355') >> s('WAIT_FOR_2307')) + cond(self._is_4355) + action(self._send_2052),
            (s('WAIT_FOR_2307') >> s('WAIT_FOR_4611')) + cond(self._is_2307) + action(self._send_4),
            (s('WAIT_FOR_4611') >> s('WAIT_FOR_3_')) + cond(self._is_4611) + action(self._send_6148),
            (s('WAIT_FOR_3_') >> s('WAIT_FOR_4611_')) + cond(self._is_3),
            (s('WAIT_FOR_4611_') >> s('WAIT_FOR_4611__')) + cond(self._is_4611) + action(self._send_772),
            (s('WAIT_FOR_4611__') >> s('END', final=1)) + cond(self._is_4611)
        ]

    def parse_args(self, **kwargs):
        set_status = kwargs.pop('set_status', None)
        equip = kwargs.pop('equip', None)
        payload = self.set_payload_ex(self, set_status, equip)
        self.payload_2052 = payload[0]
        self.payload_5124 = payload[1]
        self.payload_data = payload[2]
        S5_ATMT_Baseclass.parse_args(self, **kwargs)

    def _send_5124(self):
        payload = hex_bytes(self.payload_5124)
        pkt = H1(opcode_name='D_Connect', request_block=['DB', 0x02, 0x1404, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_32771(self):
        payload = hex_bytes('0402')
        pkt = H1(opcode_name='D_Connect', request_block=['EB', 0x02, 0x8003, 0x0404]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_33027(self):
        payload = hex_bytes('0402')
        pkt = H1(opcode_name='D_Connect', request_block=['EB', 0x02, 0x8103, 0x0404]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_2052(self):
        payload = hex_bytes(self.payload_2052)
        pkt = H1(opcode_name='D_Connect', request_block=['DB', 0x02, 0x0804, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_4(self):
        payload = hex_bytes(self.payload_data)
        pkt = H1(opcode_name='D_Connect', request_block=['MB', 0x02, 0x0004, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_6148(self):
        payload = hex_bytes('0402')
        pkt = H1(opcode_name='D_Connect', request_block=['DB', 0x02, 0x1804, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_772(self):
        payload = hex_bytes('0402000efc02000efc020002')
        pkt = H1(opcode_name='D_Connect', request_block=['DB', 0x02, 0x0304, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))


class S5_ATMT_Disconnect(S5_ATMT_Baseclass):
    def construct(self):
        self.trans = [
            (s('CLOSE_BEGIN', initial=1) >> s('WAIT_FOR_DC')) + action(self._send_dr),
            (s('WAIT_FOR_DC') >> s('END', final=1)) + cond(lambda: not self.cotp_skt.is_connected),
        ]

    def _send_dr(self):
        self.cotp_skt.disconnect()
        self.cotp_skt._clear()
        self.cotp_skt = None


class S5_ATMT_AP_OPERATE(S5_ATMT_Baseclass):
    def construct(self):
        self.trans = [
            # 第一次21252序列
            (s('BEGIN', initial=1) >> s('WAIT_FOR_65283')) + cond(self._cotp_connected) + action(self._send_21252),
            (s('WAIT_FOR_65283') >> s('WAIT_FOR_3')) + cond(self._is_65283) + action(self._send_6148),
            (s('WAIT_FOR_3') >> s('WAIT_FOR_4611')) + cond(self._is_3),
            (s('WAIT_FOR_4611') >> s('WAIT_FOR_3_')) + cond(self._is_4611) + action(self._send_1028),
            (s('WAIT_FOR_3_') >> s('WAIT_FOR_4611_')) + cond(self._is_3),
            (s('WAIT_FOR_4611_') >> s('WAIT_FOR_3__')) + cond(self._is_4611) + action(self._send_1028_),
            (s('WAIT_FOR_3__') >> s('WAIT_FOR_4611__')) + cond(self._is_3),
            (s('WAIT_FOR_4611__') >> s('WAIT_FOR_3___')) + cond(self._is_4611) + action(self._send_6148),
            (s('WAIT_FOR_3___') >> s('WAIT_FOR_4611___')) + cond(self._is_3),
            (s('WAIT_FOR_4611___') >> s('WAIT_FOR_4099')) + cond(self._is_4611) + action(self._send_5124),
            (s('WAIT_FOR_4099') >> s('WAIT_FOR_3____')) + cond(self._is_4099) + action(self._send_32771),
            (s('WAIT_FOR_3____') >> s('WAIT_FOR_4355')) + cond(self._is_3) + action(self._send_33027),
            (s('WAIT_FOR_4355') >> s('WAIT_FOR_DISCONNECT')) + cond(self._is_4355) + action(self._cotp_disconnect),
            (s('WAIT_FOR_DISCONNECT') >> s('WAIT_FOR_8_SEC')) + cond(lambda: not self._is_closing) + action(
                self._wait_8),
            (s('WAIT_FOR_DISCONNECT') >> s('WAIT_FOR_9_SEC')) + cond(lambda: self._is_closing) + action(
                self._wait_9),
            # 第二次21252序列
            (s('WAIT_FOR_8_SEC') >> s('WAIT_FOR_R_65283')) + cond(self._cotp_connected) + action(self._send_21252_),
            (s('WAIT_FOR_9_SEC') >> s('WAIT_FOR_R_65283')) + cond(self._cotp_connected) + action(self._send_21252_),
            (s('WAIT_FOR_R_65283') >> s('WAIT_FOR_R3')) + cond(self._is_65283) + action(self._send_6148),
            (s('WAIT_FOR_R3') >> s('WAIT_FOR_R4611')) + cond(self._is_3),
            (s('WAIT_FOR_R4611') >> s('WAIT_FOR_R3_')) + cond(self._is_4611) + action(self._send_6148),
            (s('WAIT_FOR_R3_') >> s('WAIT_FOR_R4611_')) + cond(self._is_3),
            (s('WAIT_FOR_R4611_') >> s('WAIT_FOR_R4099')) + cond(self._is_4611) + action(self._send_5124),
            (s('WAIT_FOR_R4099') >> s('WAIT_FOR_R3__')) + cond(self._is_4099) + action(self._send_32771),
            (s('WAIT_FOR_R3__') >> s('WAIT_FOR_R4355')) + cond(self._is_3) + action(self._send_33027),
            (s('WAIT_FOR_R4355') >> s('WAIT_FOR_R9475')) + cond(self._is_4355) + action(self._send_7684),
            (s('WAIT_FOR_R9475') >> s('WAIT_FOR_R4611__')) + cond(self._is_9475),
            (s('WAIT_FOR_R4611__') >> s('WAIT_FOR_DISCONNECT_2')) + cond(self._is_4611) + action(self._cotp_disconnect),
            (s('WAIT_FOR_DISCONNECT_2') >> s('END', final=1)) + cond(lambda: self._is_closing) + action(
                self._cotp_disconnect),
            # 开启AP的额外过程
            (s('WAIT_FOR_DISCONNECT_2') >> s('WAIT_FOR_94_SEC')) + cond(lambda: not self._is_closing, prio=1) + action(
                self._wait_94),
            (s('WAIT_FOR_94SEC') >> s('WAIT_FOR_T65283')) + cond(self._cotp_connected) + action(self._send_21252),
            (s('WAIT_FOR_T65283') >> s('WAIT_FOR_T3')) + cond(self._is_65283) + action(self._send_6148),
            (s('WAIT_FOR_T3') >> s('WAIT_FOR_T4611')) + cond(self._is_3),
            (s('WAIT_FOR_T4611') >> s('WAIT_FOR_T3_')) + cond(self._is_4611) + action(self._send_6148),
            (s('WAIT_FOR_T3_') >> s('WAIT_FOR_T4611_')) + cond(self._is_3),
            (s('WAIT_FOR_T4611_') >> s('WAIT_FOR_T4099')) + cond(self._is_4611) + action(self._send_5124),
            (s('WAIT_FOR_T4099') >> s('WAIT_FOR_T3__')) + cond(self._is_4099) + action(self._send_32771),
            (s('WAIT_FOR_T3__') >> s('WAIT_FOR_T4355')) + cond(self._is_3) + action(self._send_33027),
            (s('WAIT_FOR_T4355') >> s('WAIT_FOR_T3___')) + cond(self._is_4355) + action(self._send_1028),
            (s('WAIT_FOR_T3___') >> s('WAIT_FOR_T4611__')) + cond(self._is_3),
            (s('WAIT_FOR_T4611__') >> s('END', final=1)) + cond(self._is_4611) + action(self._cotp_disconnect)
        ]

    def parse_args(self, **kwargs):
        self._is_closing = kwargs.pop('_is_closing', False)
        COTP_ATMT_Baseclass.parse_args(self, **kwargs)

    def _send_21252(self):
        payload = hex_bytes('0402010204010401000202')
        pkt = H1(opcode_name='D_Connect', request_block=['DB', 0x02, 0x5304, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_6148(self):
        payload = hex_bytes('0402')
        pkt = H1(opcode_name='D_Connect', request_block=['DB', 0x02, 0x1804, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_1028(self):
        payload = hex_bytes('0402000ef0f0000ef0f4')
        pkt = H1(opcode_name='D_Connect', request_block=['DB', 0x02, 0x0404, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_1028_(self):
        payload = hex_bytes('0402000ef007000ef00b')
        pkt = H1(opcode_name='D_Connect', request_block=['DB', 0x02, 0x0404, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_5124(self):
        payload = hex_bytes('040200000000103f1032000efc00')
        pkt = H1(opcode_name='D_Connect', request_block=['DB', 0x02, 0x1404, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_32771(self):
        payload = hex_bytes('0402')
        pkt = H1(opcode_name='D_Connect', request_block=['EB', 0x02, 0x8003, 0x0404]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_33027(self):
        payload = hex_bytes('0402')
        pkt = H1(opcode_name='D_Connect', request_block=['EB', 0x02, 0x8103, 0x0404]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _wait_8(self):
        time.sleep(8)

    def _wait_9(self):
        time.sleep(9)

    def _wait_94(self):
        time.sleep(94)

    def _send_21252_(self):
        payload = hex_bytes('0402010204010401000202')
        pkt = H1(opcode_name='D_Connect', request_block=['DB', 0x02, 0x5304, 0x0404]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_7684(self):
        payload = hex_bytes('04020a')
        pkt = H1(opcode_name='D_Connect', request_block=['DB', 0x02, 0x1e04, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))


class S5_ATMT_S5_SERVER(S5_ATMT_Baseclass):
    def construct(self):
        self.trans = [
            # 第一次21252序列
            (s('BEGIN', initial=1) >> s('WAIT_FOR_COTP_CONNECT')),
            (s('WAIT_FOR_COTP_CONNECT') >> s('WAIT_FOR_21252')) + cond(self.is_cotp_connected),
            (s('WAIT_FOR_21252') >> s('WAIT_FOR_6148')) + cond(self._is_21252) + action(self._send_65283),
            (s('WAIT_FOR_6148') >> s('WAIT_FOR_COMMAND')) + cond(self._is_6148) + action(self._send_3_4611),
            (s('WAIT_FOR_COMMAND') >> s('WAIT_FOR_1028')) + cond(self._is_1028, prio=1) + action(self._send_3_4611_OP),
            # 控制AP
            (s('WAIT_FOR_COMMAND') >> s('WAIT_FOR_6916')) + cond(self._is_7428) + action(self._send_unknown),  # 阀门
            # 控制AP过程 AP_
            (s('WAIT_FOR_1028') >> s('AP_WAIT_FOR_6148')) + cond(self._is_1028) + action(self._send_3_4611_OP),
            (s('AP_WAIT_FOR_6148') >> s('AP_WAIT_FOR_5124')) + cond(self._is_6148) + action(self._send_3_4611_OP),
            (s('AP_WAIT_FOR_5124') >> s('AP_WAIT_FOR_32771')) + cond(self._is_5124) + action(self._send_4099),
            (s('AP_WAIT_FOR_32771') >> s('AP_WAIT_FOR_33027')) + cond(self._is_32771) + action(self._send_3),
            (s('AP_WAIT_FOR_33027') >> s('AP_WAIT_FOR_DISCONNECT')) + cond(self._is_33027) + action(self._send_4355),
            (s('AP_WAIT_FOR_DISCONNECT') >> s('AP_WAIT_FOR_9SEC')) + cond(lambda: not self._is_stopped) + action(
                self._stop_ap),
            (s('AP_WAIT_FOR_DISCONNECT') >> s('AP_WAIT_FOR_8SEC')) + cond(lambda: self._is_stopped) + action(
                self._start_ap),  # 启动AP
            (s('AP_WAIT_FOR_9SEC') >> s('AP_WAIT_FOR_COTP_CONNECT_2')) + action(self._wait_9),
            (s('AP_WAIT_FOR_8SEC') >> s('AP_WAIT_FOR_COTP_CONNECT_2')) + action(self._wait_8),
            # 控制AP第二次21252
            (s('AP_WAIT_FOR_COTP_CONNECT_2') >> s('AP_WAIT_FOR_21252')) + cond(self.is_cotp_connected),
            (s('AP_WAIT_FOR_21252') >> s('AP_WAIT_FOR_6148_2')) + cond(self._is_21252) + action(self._send_65283),
            (s('AP_WAIT_FOR_6148_2') >> s('AP_WAIT_FOR_6148_3')) + cond(self._is_6148) + action(self._send_3_4611),
            (s('AP_WAIT_FOR_6148_3') >> s('AP_WAIT_FOR_5124_2')) + cond(self._is_6148) + action(self._send_3_4611),
            (s('AP_WAIT_FOR_5124_2') >> s('AP_WAIT_FOR_32771_2')) + cond(self._is_5124) + action(self._send_4099),
            (s('AP_WAIT_FOR_32771_2') >> s('AP_WAIT_FOR_33027_2')) + cond(self._is_32771) + action(self._send_3),
            (s('AP_WAIT_FOR_33027_2') >> s('AP_WAIT_FOR_7648')) + cond(self._is_33027) + action(self._send_4355),
            (s('AP_WAIT_FOR_7648') >> s('AP_WAIT_FOR_DISCONNECT_2')) + cond(self._is_7684) + action(
                self._send_9475_4611),
            (s('AP_WAIT_FOR_DISCONNECT_2') >> s('END', final=1)) + cond(lambda: not self._is_stopped) + action(
                self._cotp_disconnect),
            #  开启AP额外21252
            (s('AP_WAIT_FOR_DISCONNECT_2') >> s('AP_WAIT_FOR_94SEC')) + cond(lambda: self._is_stopped) + action(
                self._cotp_disconnect),
            (s('AP_WAIT_FOR_94SEC') >> s('AP_WAIT_FOR_COTP_CONNECT_3')) + action(self._wait_94),
            (s('AP_WAIT_FOR_COTP_CONNECT_3') >> s('AP_WAIT_FOR_21252_2')) + cond(self.is_cotp_connected),
            (s('AP_WAIT_FOR_21252_2') >> s('AP_WAIT_FOR_6148_4')) + cond(self._is_21252) + action(self._send_65283_2),
            (s('AP_WAIT_FOR_6148_4') >> s('AP_WAIT_FOR_6148_5')) + cond(self._is_6148) + action(self._send_3_4611),
            (s('AP_WAIT_FOR_6148_5') >> s('AP_WAIT_FOR_5124_3')) + cond(self._is_6148) + action(self._send_3_4611),
            (s('AP_WAIT_FOR_5124_3') >> s('AP_WAIT_FOR_32771_3')) + cond(self._is_5124) + action(self._send_4099),
            (s('AP_WAIT_FOR_32771_3') >> s('AP_WAIT_FOR_33027_3')) + cond(self._is_32771) + action(self._send_3_OP),
            (s('AP_WAIT_FOR_33027_3') >> s('AP_WAIT_FOR_1028')) + cond(self._is_33027) + action(self._send_4355),
            (s('AP_WAIT_FOR_1028') >> s('AP_WAIT_FOR_COTP_CONNECT_3')) + cond(self._is_1028) + action(
                self._send_3_4611_OP),
            (s('AP_WAIT_FOR_COTP_CONNECT_3') >> s('END', final=1)) + action(self._cotp_disconnect),
            # 开关阀门  AA_
            (s('WAIT_FOR_6916') >> s('AA_WAIT_FOR_5124')) + cond(self._is_6916) + action(self._send_0_3_4611),
            (s('AA_WAIT_FOR_5124') >> s('AA_WAIT_FOR_32771')) + cond(self._is_5124) + action(self._send_4099),
            (s('AA_WAIT_FOR_32771') >> s('AA_WAIT_FOR_33027')) + cond(self._is_32771) + action(self._send_3_AA),
            (s('AA_WAIT_FOR_33027') >> s('AA_WAIT_FOR_2052')) + cond(self._is_33027) + action(self._send_4355),
            (s('AA_WAIT_FOR_2052') >> s('AA_WAIT_FOR_4')) + cond(self._is_2052) + action(self._send_2307_AA),
            (s('AA_WAIT_FOR_4') >> s('AA_WAIT_FOR_6148')) + cond(self._is_4) + action(self._send_4611_AA),
            (s('AA_WAIT_FOR_6148') >> s('AA_WAIT_FOR_772')) + cond(self._is_6148) + action(self._send_3_4611),
            (s('AA_WAIT_FOR_772') >> s('COMMAND_DONE')) + cond(self._is_772) + action(self._send_4611),
            (s('COMMAND_DONE') >> s('END', final=1)) + cond(timeout=H1_TIMEOUT) + action(self._cotp_disconnect),
            (s('COMMAND_DONE') >> s('AA_WAIT_FOR_32771')) + cond(self._is_5124) + action(self._send_4099),
        ]

    def is_cotp_connected(self):
        self.cotp_skt = COTPSocket(dmac='00:30:6e:0c:87:4e', smac='08:00:06:1a:11:11', sref=0x0c01,
                                   iface='以太网')
        self.cotp_skt._clear()
        if self.cotp_skt.accept():
            return False
        return True

    def parse_args(self, **kwargs):
        self._is_stopped = kwargs.pop('_is_stopped', False)
        self._equips = None
        self._operation = None
        S5_ATMT_Baseclass.parse_args(self, **kwargs)

    def _stop_ap(self):
        log.debug("正在关闭控制器AP101...")
        pass

    def _start_ap(self):
        log.debug("正在启动控制器AP101...")
        pass

    def _wait_9(self):
        time.sleep(9)

    def _wait_8(self):
        time.sleep(8)

    def _wait_94(self):
        time.sleep(94)

    def _send_65283(self):
        payload = hex_bytes('20200102000300')
        pkt = H1(opcode_name='PD_Connect', request_block=['MB', 0x02, 0xff03, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_3_4611(self):
        payload_3 = hex_bytes(
            '2020ff00ff00efe0efe8efc0efa0ef80ef409432cfffef0001000100010001000100010001000700013800050222')
        payload_4611 = hex_bytes('2020')
        pkt = H1(opcode_name='PD_Connect', request_block=['MB', 0x02, 0x0003, 0x0404]) / \
              payload_3
        self.cotp_skt.send_data(bytes.fromhex(hexstr(pkt, onlyhex=1)))
        pkt = H1(opcode_name='PD_Connect', request_block=['EB', 0x02, 0x1203, 0x0404]) / \
              payload_4611
        self.cotp_skt.send_data(raw(pkt))

    def _send_unknown(self):
        payload = hex_bytes('020a0402fe03060d0200ff00ff00efe0efe8efc0efa0ef80ef409432')
        pkt = H1(opcode_name='Unknown') / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_4099(self):
        payload = hex_bytes('2020')
        pkt = H1(opcode_name='PD_Connect', request_block=['EB', 0x02, 0x1003, 0x0404]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_3(self):
        payload = hex_bytes(
            '202000000000007600000000c000000000000001000000000000000000008000000000000000000000000d7d000000000000000000000e4e000000002000000000008000000000000000000000008000000000000000')
        pkt = H1(opcode_name='PD_Connect', request_block=['MB', 0x02, 0x0003, 0x0404]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_4355(self):
        payload = hex_bytes('2020')
        pkt = H1(opcode_name='PD_Connect', request_block=['EB', 0x02, 0xff03, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_9475_4611(self):
        payload_9475 = hex_bytes('2020')
        payload_4611 = hex_bytes('2020')
        pkt = H1(opcode_name='D_Connect', request_block=['EB', 0x02, 0x2503, 0x0404]) / \
              payload_9475
        self.cotp_skt.send_data(raw(pkt))
        pkt = H1(opcode_name='D_Connect', request_block=['EB', 0x02, 0x1203, 0x0404]) / \
              payload_4611
        self.cotp_skt.send_data(raw(pkt))
        if self._is_stopped == False:
            log.debug("AP101关闭完成")
            self._is_stopped = True
        else:
            log.debug("AP101启动完成")
            self._is_stopped = False

    def _send_65283_2(self):
        payload = hex_bytes('20200102000300')
        pkt = H1(opcode_name='PD_Connect', request_block=['MB', 0x02, 0xff03, 0x0402]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_3_OP(self):
        payload = hex_bytes(
            '2020ff000000007600000000c000000000000001000000000000000000008000000000000000000000000d7d000000000000000000000e4e000000002000000000008000000000000000000000008000000000000000')
        pkt = H1(opcode_name='PD_Connect', request_block=['MB', 0x02, 0x0003, 0x0404]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_3_4611_OP(self):
        payload_3 = hex_bytes('2020000000000000000004130037b04320230008')
        payload_4611 = hex_bytes('2020')
        pkt = H1(opcode_name='PD_Connect', request_block=['MB', 0x02, 0x0003, 0x0404]) / \
              payload_3
        self.cotp_skt.send_data(raw(pkt))
        pkt = H1(opcode_name='PD_Connect', request_block=['EB', 0x02, 0x1203, 0x0404]) / \
              payload_4611
        self.cotp_skt.send_data(raw(pkt))

    def _send_0_3_4611(self):
        payload_0 = hex_bytes(
            '20200000000000002f7d2ffd00003d343d453d563d67569956aa56bb56cc56dd56ee56ff57105721573257435754576557765787579857a957ba57cb57dc57ed57fe580f5820583158425853586458755886589758a858b958ca58db58ec58fd590e591f593059415952596359745985599659a759b859c959da59eb59fc5a0d5a1e5a2f5a405a515a625a735a845a955aa65ab75ac85ad95aea289c27c15cb35cb45cb55cb65cb75cb85cb95cba5cbb5cbc5cbd5cbe5cbf5cc05cc15cc25cc35cc45cc55cc65cc75cc82c435cc95cca5ccb5ccc5ccd5cce5ccf5cd05cd15cd25cd35cd45cd55cd65cd75cd85cd95cda5cdb5cdc5cdd5cde5cdf5ce05ce15ce25ce3')
        payload_3 = hex_bytes(
            '20205ce45ce52aa42a1d2996290f2ef45ce65ce75ce85ce95cea5ceb5cec5ced5cee5cef5cf05cf15cf25cf35cf45cf55cf65cf75cf85cf95cfa5cfb5cfc5cfd5cfe5cff5d005d015d025d035d045d055d065d075d085d095d0a5d0b5d0c5d0d5d0e5d0f5d105d115d122d362cd05d135d145d152d472cbf2cae2cf22ce12d032c9d2d142d252c855d165d175d185d195d1a5d1b5d1c5d1d5d1e5d1f5d205d215d225d235d245d255d265d275d285d295d2a5d2b5d2c5d2d5d2e2dde5d2f5d305d315d325d335d345d355d365d375d385d395d3a5d3b5d3c5d3d5d3e5d3f5d405d415d425d435d445d455d465d475d485d495d4a5d4b5d4c5d4d5d4e5d4f5d502b28')
        payload_4611 = hex_bytes('2020')
        pkt = H1(opcode_name='PD_Connect', request_block=['MB', 0x02, 0x0000, 0x0404]) / \
              payload_0
        self.cotp_skt.send_data(raw(pkt))
        pkt = H1(opcode_name='PD_Connect', request_block=['MB', 0x02, 0x0003, 0x0404]) / \
              payload_3
        self.cotp_skt.send_data(raw(pkt))
        pkt = H1(opcode_name='PD_Connect', request_block=['EB', 0x02, 0x1203, 0x0404]) / \
              payload_4611
        self.cotp_skt.send_data(raw(pkt))

    def _send_3_AA(self):
        payload = hex_bytes(
            '2020ff000000000000000000c000000000000001000000000000000000008000000000000000000000000d7d000000000000000000000e4e000000002000000000008000000000000000000000008000000000000000')
        pkt = H1(opcode_name='PD_Connect', request_block=['MB', 0x02, 0x0003, 0x0404]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_2307_AA(self):

        payload = hex_bytes('2020')
        pkt = H1(opcode_name='PD_Connect', request_block=['EB', 0x02, 0x0903, 0x0404]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_4611_AA(self):
        text = "正在操作阀门 {}：命令为{}"
        log.debug(text.format(self._equips, self._operation))
        payload = hex_bytes('2020')
        pkt = H1(opcode_name='PD_Connect', request_block=['EB', 0x02, 0x1203, 0x0404]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))

    def _send_4611(self):
        payload = hex_bytes('2020')
        pkt = H1(opcode_name='PD_Connect', request_block=['EB', 0x02, 0x1203, 0x0404]) / \
              payload
        self.cotp_skt.send_data(raw(pkt))
        log.debug("阀门操作完成")

    def _is_2052(self):
        buf = self.cotp_skt.recv_data_block(1)
        h1_pkt = dissect_h1_ex(*buf)
        if int.from_bytes(h1_pkt.Address_within_memory_block, byteorder='big') == 2052:
            payload = h1_pkt.getlayer(Raw).load
            self._equips = EQUIP_NAME[payload[3:]]
            return True
        return False

    def _is_4(self):
        buf = self.cotp_skt.recv_data_block(1)
        h1_pkt = dissect_h1_ex(*buf)
        if int.from_bytes(h1_pkt.Address_within_memory_block, byteorder='big') == 2052:
            payload = h1_pkt.getlayer(Raw).load
            self._operation = EQUIP_NAME[self._equips][payload.hex()]
            return True
        return False

    def _is_772(self):
        buf = self.cotp_skt.recv_data_block(1)
        return self.verifyDWNR(buf, 772)
