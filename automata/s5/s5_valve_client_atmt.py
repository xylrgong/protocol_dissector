from automata.s5.s5_client_baseclass import *


class S5_ATMT_DCONNECT(S5_CLIENT_ATMT_Baseclass):
    def construct(self):
        self.trans = [
            # 建立动态连接
            (s('BEGIN', initial=1) >> s('WAIT_FOR_COTP_CONNECT')) + cond(self._cotp_connected, prio=1),
            (s('WAIT_FOR_COTP_CONNECT') >> s('WAIT_FOR_D_65283')) + action(self.send_dwnr, dwnr='21252_'),
            (s('WAIT_FOR_D_65283') >> s('WAIT_FOR_D_3')) + cond(self.get_cond(65283, 'dc_is_65283')) + action(
                self.send_dwnr, dwnr='6148'),
            (s('WAIT_FOR_D_3') >> s('WAIT_FOR_D_4611')) + cond(self.get_cond(3, 'dc_is_3')),
            (s('WAIT_FOR_D_4611') >> s('WAIT_FOR_D_UNKNOWN')) + cond(self.get_cond(4611, 'dc_is_4611'))
            + action(self.send_dwnr, dwnr='7428'),
            (s('WAIT_FOR_D_UNKNOWN') >> s('WAIT_FOR_D_0')) + cond(self._is_unknown)
            + action(self.send_dwnr, dwnr='6916'),
            (s('WAIT_FOR_D_0') >> s('WAIT_FOR_D_3_')) + cond(self.get_cond(0, 'dc_is_0')),
            (s('WAIT_FOR_D_3_') >> s('WAIT_FOR_D_4611_')) + cond(self.get_cond(3, 'dc_is_3_')),
            (s('WAIT_FOR_D_4611_') >> s('D_CONNECTED', final=1)) + cond(self.get_cond(4611, 'dc_is_4611_'))
        ]

    def parse_args(self, **kwargs):
        self.cotp_skt = kwargs.pop('cotp_skt', None)
        S5_CLIENT_ATMT_Baseclass.parse_args(self, **kwargs)

    def _cotp_connected(self):
        if not self.cotp_skt.connect():
            self.is_dconnected = True
            return True
        return False

    def _is_unknown(self):
        buf = self.cotp_skt.recv_data_block(1)
        pkt = dissect_h1_ex(*buf)
        if pkt.Opcode == 142:
            return True
        return False


class S5_VALVE_OPERATE_ATMT(S5_CLIENT_ATMT_Baseclass):
    def construct(self):
        self.trans = [
            # 发出阀门操作请求
            (s('VALVE_BEGIN', initial=1) >> s('WAIT_FOR_4099')) + action(self.send_dwnr, dwnr='5124'),
            (s('WAIT_FOR_4099') >> s('WAIT_FOR_3')) + cond(self.get_cond(4099, 'valve_is_4099')) + action(
                self.send_dwnr, dwnr='32771'),
            (s('WAIT_FOR_3') >> s('WAIT_FOR_4355')) + cond(self.get_cond(3, 'valve_is_3')) + action(self.send_dwnr,
                                                                                                    dwnr='33027'),
            (s('WAIT_FOR_4355') >> s('WAIT_FOR_2307')) + cond(self.get_cond(4355, 'valve_is_4355')) + action(
                self.send_dwnr_2052),
            (s('WAIT_FOR_2307') >> s('WAIT_FOR_4611')) + cond(self.get_cond(2307, 'valve_is_2307')) + action(
                self.send_dwnr_4),
            (s('WAIT_FOR_4611') >> s('WAIT_FOR_3_')) + cond(self.get_cond(4611, 'valve_is_4611')) + action(
                self.send_dwnr, dwnr='6148'),
            (s('WAIT_FOR_3_') >> s('WAIT_FOR_4611_')) + cond(self.get_cond(3, 'valve_is_3_')),
            (s('WAIT_FOR_4611_') >> s('WAIT_FOR_4611__')) + cond(self.get_cond(4611, 'valve_is_4611_')) + action(
                self.send_dwnr, dwnr='772'),
            (s('WAIT_FOR_4611__') >> s('END', final=1)) + cond(self.get_cond(4611, 'valve_is_4611__')) + action(
                self.wait_for_operate),
        ]

    def parse_args(self, **kwargs):
        self._valve_name = kwargs.pop('valve_name', '')
        self._op_type = self._valve_name + kwargs.pop('op_type', '')
        self.cotp_skt = kwargs.pop('cotp_skt', None)
        S5_CLIENT_ATMT_Baseclass.parse_args(self, **kwargs)

    # 2052的负载指定了阀门名称
    def send_dwnr_2052(self):
        pkt = H1(*h1_payload[self._valve_name][0]) / hex_bytes(h1_payload[self._valve_name][1])
        print(2052)
        self.cotp_skt.send_data(raw(pkt))

    # 4的负载指定了阀门操作类型
    def send_dwnr_4(self):
        pkt = H1(*h1_payload[self._op_type][0]) / hex_bytes(h1_payload[self._op_type][1])
        print(4)
        self.cotp_skt.send_data(raw(pkt))

    def wait_for_operate(self):
        print('waiting for oprating...')
        time.sleep(1)
        print(self._op_type+'_complete')

# class S5_ATMT_Disconnect(S5_CLIENT_ATMT_Baseclass):
#     def construct(self):
#         self.trans = [
#             (s('DISCONN_BEGIN', initial=1) >> s('WAIT_FOR_DISCONN')) + action(self._do_disconnect),
#             (s('WAIT_FOR_DISCONN') >> s('END', final=1))
#         ]
#
#     def parse_args(self, **kwargs):
#         self.cotp_skt = kwargs.pop('cotp_skt', None)
#         S5_CLIENT_ATMT_Baseclass.parse_args(self, **kwargs)
#
#     def _do_disconnect(self):
#         self.cotp_skt.disconnect()

