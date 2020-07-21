from automata.s5.s5_server_baseclass import *


class S5_SERVER_ATMT(S5_SERVER_ATMT_Baseclass):
    def construct(self):
        self.trans = [
            (s('SERVER_BEGIN', initial=1) >> s('WAIT_FOR_COTP_CONNECT')),
            (s('WAIT_FOR_COTP_CONNECT') >> s('WAIT_FOR_21252')) + cond(self.get_conn('get_conn1')),
            (s('WAIT_FOR_21252') >> s('WAIT_FOR_6148')) + cond(self.get_cond(21252, 'svr_is_21252')) + action(self.send_dwnr, dwnr='65283'),
            (s('WAIT_FOR_6148') >> s('WAIT_FOR_COMMAND')) + cond(self.get_cond(6148, 'svr_is_6148')) + action(self.send_dwnr, dwnr='3', dwnr2='4611'),
            # 阀门操作
            (s('WAIT_FOR_COMMAND') >> s('WAIT_FOR_6916')) + cond(self.sver_is_7428) + action(self.send_dwnr, dwnr='unknown'),
            (s('WAIT_FOR_6916') >> s('AA_WAIT_FOR_5124')) + cond(self.get_cond(6916, 'valve_is_6916')) + action(self.send_dwnr,dwnr='0',dwnr2='3_valve',dwnr3='4611'),
            (s('AA_WAIT_FOR_5124') >> s('AA_WAIT_FOR_32771')) + cond(self.get_cond(5124, 'vale_is_5124')) + action(self.send_dwnr,dwnr='4099'),
            (s('AA_WAIT_FOR_32771') >> s('AA_WAIT_FOR_33027')) + cond(self.get_cond(32771, 'valve_is_32771')) + action(self.send_dwnr, dwnr='3_valve_2'),
            (s('AA_WAIT_FOR_33027') >> s('AA_WAIT_FOR_2052')) + cond(self.get_cond(33027, 'valve_is_33027')) + action(self.send_dwnr, dwnr='4355'),
            (s('AA_WAIT_FOR_2052') >> s('AA_WAIT_FOR_4')) + cond(self.valve_is_2052) + action(self.send_dwnr, dwnr='2307'),
            (s('AA_WAIT_FOR_4') >> s('AA_WAIT_FOR_6148')) + cond(self.valve_is_4) + action(self.send_dwnr, dwnr='4611'),
            (s('AA_WAIT_FOR_6148') >> s('AA_WAIT_FOR_772')) + cond(self.get_cond(6148, 'valve_is_6148')) + action(self.send_dwnr, dwnr='3', dwnr2='4611'),
            (s('AA_WAIT_FOR_772') >> s('COMMAND_DONE')) + cond(self.get_cond(772, 'valve_is_772')) + action(self.send_dwnr, dwnr='4611'),
            (s('COMMAND_DONE') >> s('AA_WAIT_FOR_32771')) +cond(self.get_cond(5124, 'vale_is_5124_'), prio=1) + action(self.send_dwnr, dwnr='4099'),
            (s('COMMAND_DONE') >> s('VALVE_END', final=1)) + cond(self.already_disconnected),

            # 控制AP过程
            (s('WAIT_FOR_COMMAND') >> s('WAIT_FOR_1028')) + cond(self._is_1028, prio=1) + action(self.send_dwnr, dwnr='3_ap', dwnr2='4611'),
            (s('WAIT_FOR_1028') >> s('AP_WAIT_FOR_6148')) + cond(self.get_cond(1028, 'ap_is_1028')) + action(self.send_dwnr, dwnr='3_ap', dwnr2='4611'),
            (s('AP_WAIT_FOR_6148') >> s('AP_WAIT_FOR_5124')) + cond(self.get_cond(6148, 'ap_is_6148')) + action(self.send_dwnr, dwnr='3_ap', dwnr2='4611'),
            (s('AP_WAIT_FOR_5124') >> s('AP_WAIT_FOR_32771')) + cond(self.get_cond(5124, 'ap_is_5124')) + action(self.send_dwnr, dwnr='4099'),
            (s('AP_WAIT_FOR_32771') >> s('AP_WAIT_FOR_33027')) + cond(self.get_cond(32771, 'ap_is_32771')) + action(self.send_dwnr, dwnr='3_'),
            (s('AP_WAIT_FOR_33027') >> s('AP_WAIT_FOR_DISCONNECT')) + cond(self.get_cond(33027, 'ap_is_33027')) + action(self.send_dwnr, dwnr='4355'),
            (s('AP_WAIT_FOR_DISCONNECT') >> s('AP_WAIT_FOR_9SEC')) + cond(lambda: not self._is_stopped) + action(
                self._stop_ap),
            (s('AP_WAIT_FOR_DISCONNECT') >> s('AP_WAIT_FOR_8SEC')) + cond(lambda: self._is_stopped) + action(
                self._start_ap),  # 启动AP
            (s('AP_WAIT_FOR_9SEC') >> s('AP_WAIT_FOR_COTP_CONNECT_2')) + action(self._wait_9),
            (s('AP_WAIT_FOR_8SEC') >> s('AP_WAIT_FOR_COTP_CONNECT_2')) + action(self._wait_8),
            # 控制AP第二次21252
            (s('AP_WAIT_FOR_COTP_CONNECT_2') >> s('AP_WAIT_FOR_21252')) + cond(self.get_conn('get_conn2')),
            (s('AP_WAIT_FOR_21252') >> s('AP_WAIT_FOR_6148_2')) + cond(self.get_cond(21252, 'ap2_is_21252')) + action(self.send_dwnr, dwnr='65283'),
            (s('AP_WAIT_FOR_6148_2') >> s('AP_WAIT_FOR_6148_3')) + cond(self.get_cond(6148, 'ap2_is_6148')) + action(self.send_dwnr, dwnr='3', dwnr2='4611'),
            (s('AP_WAIT_FOR_6148_3') >> s('AP_WAIT_FOR_5124_2')) + cond(self.get_cond(6148, 'ap2_is_6148_')) + action(self.send_dwnr, dwnr='3', dwnr2='4611'),
            (s('AP_WAIT_FOR_5124_2') >> s('AP_WAIT_FOR_32771_2')) + cond(self.get_cond(5124, 'ap2_is_5124')) + action(self.send_dwnr, dwnr='4099'),
            (s('AP_WAIT_FOR_32771_2') >> s('AP_WAIT_FOR_33027_2')) + cond(self.get_cond(32771, 'ap2_is_32771')) + action(self.send_dwnr, dwnr='3_'),
            (s('AP_WAIT_FOR_33027_2') >> s('AP_WAIT_FOR_7648')) + cond(self.get_cond(33027, 'ap2_is_33027')) + action(self.send_dwnr, dwnr='4355'),
            (s('AP_WAIT_FOR_7648') >> s('AP_WAIT_FOR_DISCONNECT_2')) + cond(self.get_cond(7684, 'ap2_is_7684')) + action(
                self.send_dwnr, dwnr='9475', dwnr2='4611'),
            (s('AP_WAIT_FOR_DISCONNECT_2') >> s('END', final=1)) + cond(lambda: not self._is_stopped) + action(self._ap_done),
            #  开启AP额外21252
            (s('AP_WAIT_FOR_DISCONNECT_2') >> s('AP_WAIT_FOR_94SEC')) + cond(lambda: self._is_stopped) + action(self.get_skt),
            (s('AP_WAIT_FOR_94SEC') >> s('AP_WAIT_FOR_COTP_CONNECT_3')) + action(self._wait_94),
            (s('AP_WAIT_FOR_COTP_CONNECT_3') >> s('AP_WAIT_FOR_21252_2')) + cond(self.get_conn('get_conn3')),
            (s('AP_WAIT_FOR_21252_2') >> s('AP_WAIT_FOR_6148_4')) + cond(self.get_cond(21252, 'ap3_is_21252')) + action(self.send_dwnr, dwnr='65283'),
            (s('AP_WAIT_FOR_6148_4') >> s('AP_WAIT_FOR_6148_5')) + cond(self.get_cond(6148, 'ap3_is_6148')) + action(self.send_dwnr, dwnr='3', dwnr2='4611'),
            (s('AP_WAIT_FOR_6148_5') >> s('AP_WAIT_FOR_5124_3')) + cond(self.get_cond(6148, 'ap3_is_6148_')) + action(self.send_dwnr, dwnr='3', dwnr2='4611'),
            (s('AP_WAIT_FOR_5124_3') >> s('AP_WAIT_FOR_32771_3')) + cond(self.get_cond(5124, 'ap3_is_5124')) + action(self.send_dwnr, dwnr='4099'),
            (s('AP_WAIT_FOR_32771_3') >> s('AP_WAIT_FOR_33027_3')) + cond(self.get_cond(32771, 'ap3_is_32771')) + action(self.send_dwnr, dwnr='3_'),
            (s('AP_WAIT_FOR_33027_3') >> s('AP_WAIT_FOR_1028')) + cond(self.get_cond(33027, 'ap3_is_33027')) + action(self.send_dwnr, dwnr='4355'),
            (s('AP_WAIT_FOR_1028') >> s('AP_WAIT_FOR_COTP_CONNECT_3')) + cond(self.get_cond(1028, 'ap3_is_1028')) + action(
                self.send_dwnr, dwnr='3_ap', dwnr2='4611'),
            (s('AP_WAIT_FOR_COTP_CONNECT_3') >> s('END', final=1))+action(self._ap_done)
        ]
    def parse_args(self, **kwargs):
        self.server_cotp_skt = kwargs.pop('sever_cotp_skt', None)
        self.server_cotp_skt2 = kwargs.pop('sever_cotp_skt2', None)
        self.server_cotp_skt3 = kwargs.pop('sever_cotp_skt3', None)
        self._is_stopped = kwargs.pop('_is_stopped', False)
        self._ap_callback = kwargs.pop('ap_callback', None)
        self._equips = None
        self._operation = None
        self._recv_queue = []
        S5_SERVER_ATMT_Baseclass.parse_args(self, **kwargs)

    def get_skt(self):
        self.server_cotp_skt = None
        self.server_cotp_skt=self.server_cotp_skt3

    def already_disconnected(self):
        time.sleep(H1_TIMEOUT)
        if not self.server_cotp_skt.is_connected:
            return True
        return False

    def _ap_done(self):
        self._ap_callback()

    def sver_is_7428(self):
        buf = self.server_cotp_skt.recv_data_block(1)
        h1_pkt = dissect_h1_ex(*buf)
        pkt_DWNR = int.from_bytes(h1_pkt.Address_within_memory_block, byteorder='big')
        log.debug('收到序列号：{}'.format(pkt_DWNR))
        if pkt_DWNR == 7428:
            return True
        self._recv_queue.append(pkt_DWNR)

    def _is_1028(self):
        # 先判定是否收到7428 如果不是则存入列表 此时再做判断
        if len(self._recv_queue):
            return self._recv_queue.pop() == 1028
        return False

    def valve_is_2052(self):
        buf = self.server_cotp_skt.recv_data_block(1)
        h1_pkt = dissect_h1_ex(*buf)
        if int.from_bytes(h1_pkt.Address_within_memory_block, byteorder='big') == 2052:
            payload = h1_pkt.getlayer(Raw).load
            self._equips = EQUIP_NAME[payload[3:]]
            return True
        return False

    def valve_is_4(self):
        buf = self.server_cotp_skt.recv_data_block(1)
        h1_pkt = dissect_h1_ex(*buf)
        if int.from_bytes(h1_pkt.Address_within_memory_block, byteorder='big') == 4:
            payload = h1_pkt.getlayer(Raw).load
            self._operation = OPERATE_DATA[self._equips][payload.hex()]
            return True
        return False

    def _stop_ap(self):
        log.debug("正在关闭控制器AP101...")

        time.sleep(5)
        pass

    def _start_ap(self):
        log.debug("正在启动控制器AP101...")
        time.sleep(5)
        pass

    def _wait_9(self):
        # time.sleep(9)
        self.server_cotp_skt = None
        self.server_cotp_skt = self.server_cotp_skt2

    def _wait_8(self):
        # time.sleep(8)
        self.server_cotp_skt = None
        self.server_cotp_skt = self.server_cotp_skt2

    def _wait_94(self):
        # time.sleep(94)
        pass