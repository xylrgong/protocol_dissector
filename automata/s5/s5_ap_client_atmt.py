from automata.s5.s5_client_baseclass import *

class S5_ATMT_AP_OPERATE(S5_CLIENT_ATMT_Baseclass):
    def construct(self):
        self.trans = [
            # 第一次21252序列
            (s('BEGIN', initial=1) >> s('WAIT_FOR_65283')) + cond(self.get_conn('cotp_conn1')) + action(self.send_dwnr, dwnr='21252'),
            (s('WAIT_FOR_65283') >> s('WAIT_FOR_3')) + cond(self.get_cond(65283, 'ap1_is_65283')) + action(self.send_dwnr, dwnr='6148'),
            (s('WAIT_FOR_3') >> s('WAIT_FOR_4611')) + cond(self.get_cond(3, 'ap1_is_3')),
            (s('WAIT_FOR_4611') >> s('WAIT_FOR_3_')) + cond(self.get_cond(4611, 'ap1_is_4611')) + action(self.send_dwnr, dwnr='1028'),
            (s('WAIT_FOR_3_') >> s('WAIT_FOR_4611_')) + cond(self.get_cond(3, 'ap1_is_3_')),
            (s('WAIT_FOR_4611_') >> s('WAIT_FOR_3__')) + cond(self.get_cond(4611, 'ap1_is_4611_')) + action(self.send_dwnr, dwnr='1028_'),
            (s('WAIT_FOR_3__') >> s('WAIT_FOR_4611__')) + cond(self.get_cond(3, 'ap1_is_3__')),
            (s('WAIT_FOR_4611__') >> s('WAIT_FOR_3___')) + cond(self.get_cond(4611, 'ap1_is_4611__')) + action(self.send_dwnr, dwnr='6148'),
            (s('WAIT_FOR_3___') >> s('WAIT_FOR_4611___')) + cond(self.get_cond(3, 'ap1_is_3___')),
            (s('WAIT_FOR_4611___') >> s('WAIT_FOR_4099')) + cond(self.get_cond(4611, 'ap1_is_4611___')) + action(self.send_dwnr, dwnr='5124_ap'),
            (s('WAIT_FOR_4099') >> s('WAIT_FOR_3____')) + cond(self.get_cond(4099, 'ap1_is_4099')) + action(self.send_dwnr, dwnr='32771'),
            (s('WAIT_FOR_3____') >> s('WAIT_FOR_4355')) + cond(self.get_cond(3, 'ap1_is_3____')) + action(self.send_dwnr, dwnr='33027'),
            (s('WAIT_FOR_4355') >> s('WAIT_FOR_DISCONNECT')) + cond(self.get_cond(4355, 'ap1_is_4355')) + action(self._cotp_disconnect),
            (s('WAIT_FOR_DISCONNECT') >> s('WAIT_FOR_8_SEC')) + cond(lambda: self._is_starting) + action(
                self._wait_8),
            (s('WAIT_FOR_DISCONNECT') >> s('WAIT_FOR_9_SEC')) + cond(lambda:not self._is_starting) + action(
                self._wait_9),
            # 第二次21252序列
            (s('WAIT_FOR_8_SEC') >> s('WAIT_FOR_AP2_65283')) + cond(self.get_conn('cotp_conn_stt')) + action(self.send_dwnr, dwnr='21252_'),
            (s('WAIT_FOR_9_SEC') >> s('WAIT_FOR_AP2_65283')) + cond(self.get_conn('cotp_conn_stp')) + action(self.send_dwnr, dwnr='21252_'),
            (s('WAIT_FOR_AP2_65283') >> s('WAIT_FOR_AP2_3')) + cond(self.get_cond(65283, 'ap2_is_65283')) + action(self.send_dwnr, dwnr='6148'),
            (s('WAIT_FOR_AP2_3') >> s('WAIT_FOR_AP2_4611')) + cond(self.get_cond(3, 'ap2_is_3')),
            (s('WAIT_FOR_AP2_4611') >> s('WAIT_FOR_AP2_3_')) + cond(self.get_cond(4611, 'ap2_is_4611')) + action(self.send_dwnr, dwnr='6148'),
            (s('WAIT_FOR_AP2_3_') >> s('WAIT_FOR_AP2_4611_')) + cond(self.get_cond(3, 'ap2_is_3_')),
            (s('WAIT_FOR_AP2_4611_') >> s('WAIT_FOR_AP2_4099')) + cond(self.get_cond(4611, 'ap2_is_4611_')) + action(self.send_dwnr, dwnr='5124_ap'),
            (s('WAIT_FOR_AP2_4099') >> s('WAIT_FOR_AP2_3__')) + cond(self.get_cond(4099, 'ap2_is_4099')) + action(self.send_dwnr, dwnr='32771'),
            (s('WAIT_FOR_AP2_3__') >> s('WAIT_FOR_AP2_4355')) + cond(self.get_cond(3, 'ap2_is_3__')) + action(self.send_dwnr, dwnr='33027'),
            (s('WAIT_FOR_AP2_4355') >> s('WAIT_FOR_AP2_9475')) + cond(self.get_cond(4355, 'ap2_is_4355')) + action(self.send_dwnr, dwnr='7684'),
            (s('WAIT_FOR_AP2_9475') >> s('WAIT_FOR_AP2_4611__')) + cond(self.get_cond(9475, 'ap2_is_9475')),
            (s('WAIT_FOR_AP2_4611__') >> s('WAIT_FOR_DISCONNECT_2')) + cond(self.get_cond(4611, 'ap2_is_4611__')) + action(self._cotp_disconnect),
            (s('WAIT_FOR_DISCONNECT_2') >> s('AP_END', final=1)) + cond(lambda:not self._is_starting) + action(
                self._cotp_disconnect, ap_done=True),
            # 开启AP的额外过程
            (s('WAIT_FOR_DISCONNECT_2') >> s('WAIT_FOR_94_SEC')) + cond(lambda: self._is_starting, prio=1) + action(
                self._wait_94),
            (s('WAIT_FOR_94_SEC') >> s('WAIT_FOR_AP3_65283')) + cond(self.get_conn('get_conn3')) + action(self.send_dwnr, dwnr='21252'),  #
            (s('WAIT_FOR_AP3_65283') >> s('WAIT_FOR_AP3_3')) + cond(self.get_cond(65283, 'ap3_is_65283')) + action(self.send_dwnr, dwnr='6148'),
            (s('WAIT_FOR_AP3_3') >> s('WAIT_FOR_AP3_4611')) + cond(self.get_cond(3, 'ap3_is_3')),
            (s('WAIT_FOR_AP3_4611') >> s('WAIT_FOR_AP3_3_')) + cond(self.get_cond(4611, 'ap3_is_4611')) + action(self.send_dwnr, dwnr='6148'),
            (s('WAIT_FOR_AP3_3_') >> s('WAIT_FOR_AP3_4611_')) + cond(self.get_cond(3, 'ap3_is_3_')),
            (s('WAIT_FOR_AP3_4611_') >> s('WAIT_FOR_AP3_4099')) + cond(self.get_cond(4611, 'ap3_is_4611_')) + action(self.send_dwnr, dwnr='5124_ap'),
            (s('WAIT_FOR_AP3_4099') >> s('WAIT_FOR_AP3_3__')) + cond(self.get_cond(4099, 'ap3_is_4099')) + action(self.send_dwnr, dwnr='32771'),
            (s('WAIT_FOR_AP3_3__') >> s('WAIT_FOR_AP3_4355')) + cond(self.get_cond(3, 'ap3_is_3__')) + action(self.send_dwnr, dwnr='33027'),
            (s('WAIT_FOR_AP3_4355') >> s('WAIT_FOR_AP3_3___')) + cond(self.get_cond(4355, 'ap3_is_4355')) + action(self.send_dwnr, dwnr='1028'),
            (s('WAIT_FOR_AP3_3___') >> s('WAIT_FOR_AP3_4611__')) + cond(self.get_cond(3, 'ap3_is_3___')),
            (s('WAIT_FOR_AP3_4611__') >> s('AP_END', final=1)) + cond(self.get_cond(4611, 'ap3_is_4611__')) + action(self._cotp_disconnect, ap_done=True)
        ]

    def parse_args(self, **kwargs):
        self.cotp_skt = kwargs.pop('cotp_skt', None)
        self._is_starting = kwargs.pop('is_starting', False)
        self._ap_callback = kwargs.pop('ap_callback', False)
        S5_CLIENT_ATMT_Baseclass.parse_args(self, **kwargs)


    def _cotp_disconnect(self, ap_done=False):
        # AP操作完成时改写AP运行状态
        if ap_done:
            self._ap_callback()
        # 主动断开COTP连接
        if self.is_dconnected == True:
            self.cotp_skt.disconnect()
            self.is_dconnected = False
        return True

    def _wait_8(self):
        log.debug('waiting for ap starting...')
        time.sleep(8)

    def _wait_9(self):
        log.debug('waiting for ap stopping...')
        time.sleep(9)


    def _wait_94(self):
        # time.sleep(94)
        time.sleep(9)
