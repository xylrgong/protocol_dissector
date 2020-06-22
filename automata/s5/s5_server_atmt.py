from automata.s5.s5_server_baseclass import *


class S5_SERVER_ATMT(S5_SERVER_ATMT_Baseclass):
    def construct(self):
        self.trans = [
            (s('VALVE_BEGIN', initial=1) >> s('WAIT_FOR_COTP_CONNECT')),
            (s('WAIT_FOR_COTP_CONNECT') >> s('WAIT_FOR_21252')) + cond(self.is_cotp_connected),
            (s('WAIT_FOR_21252') >> s('WAIT_FOR_6148')) + cond(self.get_cond(21252, 'svr_is_21252')) + action(self.send_dwnr, dwnr='65283'),
            (s('WAIT_FOR_6148') >> s('WAIT_FOR_COMMAND')) + cond(self.get_cond(6148, 'svr_is_6148')) + action(self.send_dwnr, dwnr='3', dwnr2='4611'),
            (s('WAIT_FOR_COMMAND') >> s('WAIT_FOR_6916')) + cond(self.get_cond(7428, 'sver_is_7428')) + action(self.send_dwnr, dwnr='unknown'),  # 阀门
            (s('WAIT_FOR_6916') >> s('AA_WAIT_FOR_5124')) + cond(self.get_cond(6916, 'valve_is_6916')) + action(self.send_dwnr,dwnr='0',dwnr2='3_valve',dwnr3='4611'),
            (s('AA_WAIT_FOR_5124') >> s('AA_WAIT_FOR_32771')) + cond(self.get_cond(5124, 'vale_is_5124')) + action(self.send_dwnr,dwnr='4099'),
            (s('AA_WAIT_FOR_32771') >> s('AA_WAIT_FOR_33027')) + cond(self.get_cond(32771,'valve_is_32771')) + action(self.send_dwnr, dwnr='3_valve_2'),
            (s('AA_WAIT_FOR_33027') >> s('AA_WAIT_FOR_2052')) + cond(self.get_cond(33027, 'valve_is_33027')) + action(self.send_dwnr, dwnr='4355'),
            (s('AA_WAIT_FOR_2052') >> s('AA_WAIT_FOR_4')) + cond(self.valve_is_2052) + action(self.send_dwnr, dwnr='2307'),
            (s('AA_WAIT_FOR_4') >> s('AA_WAIT_FOR_6148')) + cond(self.valve_is_4) + action(self.send_dwnr, dwnr='4611'),
            (s('AA_WAIT_FOR_6148') >> s('AA_WAIT_FOR_772')) + cond(self.get_cond(6148, 'valve_is_6148')) + action(self.send_dwnr, dwnr='3', dwnr2='4611'),
            (s('AA_WAIT_FOR_772') >> s('COMMAND_DONE')) + cond(self.get_cond(772, 'valve_is_772')) + action(self.send_dwnr, dwnr='4611'),
            (s('COMMAND_DONE') >> s('AA_WAIT_FOR_32771')) +cond(lambda :self.get_cond(5124, 'vale_is_5124_'), prio=1) + action(self.send_dwnr, dwnr='4099'),
            (s('COMMAND_DONE') >> s('VALVE_END', final=1)) + cond(self.already_disconnected),
        ]
    def parse_args(self, **kwargs):
        self._is_stopped = kwargs.pop('_is_stopped', False)
        self._equips = None
        self._operation = None
        params = kwargs.pop('params', None)
        self.server_cotp_skt = COTPSocket(dmac=params.dmac, smac=params.smac, sref=params.sref, iface=params.iface)
        S5_SERVER_ATMT_Baseclass.parse_args(self, **kwargs)

    def is_cotp_connected(self):
        if self.server_cotp_skt.accept():
            return False
        return True

    def _cotp_disconnect(self):
        self.server_cotp_skt.disconnect()
        self.server_cotp_skt = None

    def already_disconnected(self):
        time.sleep(H1_TIMEOUT)
        if not self.server_cotp_skt.is_connected:
            return True
        return False

    def valve_is_2052(self):
        buf = self.cotp_skt.recv_data_block(1)
        h1_pkt = dissect_h1_ex(*buf)
        if int.from_bytes(h1_pkt.Address_within_memory_block, byteorder='big') == 2052:
            payload = h1_pkt.getlayer(Raw).load
            self._equips = EQUIP_NAME[payload[3:]]
            return True
        return False

    def valve_is_4(self):
        buf = self.cotp_skt.recv_data_block(1)
        h1_pkt = dissect_h1_ex(*buf)
        if int.from_bytes(h1_pkt.Address_within_memory_block, byteorder='big') == 4:
            payload = h1_pkt.getlayer(Raw).load
            self._operation = EQUIP_NAME[self._equips][payload.hex()]
            return True
        return False

