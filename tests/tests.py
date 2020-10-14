from tests.test_passive_atmt import *
from tests.test_atmt import *
from tests.test_giop_1 import *
from automata.cotp.cotp_config import *
from proxy.proxy_manager import *
from protocols.packet_giop import *
from utils.utils import *


class Test(object):
    def __init__(self):
        pass

    def run(self):
        Test_GIOP().test_giop_atmt()

        print('Sleeping...')
        time.sleep(99999)

    # 添加测试代码，然后在 run() 中调用

    def test_packet_giop(self):
        pkt = GIOP(type='Request',
                   RequestID=1512756,
                   KeyAddress=h2b('14010f0052535403952b5f502900000300000001000000040000'),
                   RequestOperation='idl_rcv_rdb_receive_data',
                   StubData=h2b('5e00000009000000024b505300000000'))
        pkt.show()
        hexdump(pkt)
        print('\n')

        pkt2 = GIOP(type='Reply',
                    RequestID=1512578,
                    ReplyStatus=0)
        pkt2.show()
        hexdump(pkt2)
        print(to_hex(pkt2))
        print('\n')

        buf = '47494F5001020100640000003415170003000000000000001B00000014010F0052535403952B5F50290000030000000100000004000000001900000069646C5F7263765F7264625F726563656976655F646174610000000000000000000000005E00000009000000024B505300000000'
        pkt3 = GIOP_Request(h2b(buf))
        pkt3.show()
        hexdump(pkt3)
        print('\n')

        buf2 = '47494F50 010201 00 0D000000 82141700000000000000000000'

        pkt4 = GIOP_Reply(h2b(buf2))
        pkt4.show()
        hexdump(pkt4)

    def test_proxy_cotp(self):
        pman = ProxyManager(iface='以太网 2')
        pman.run()

        pkt1 = COTP_Dot3(dst='AA:AA:AA:AA:AA:AA', src='BB:BB:BB:BB:BB:BB') / \
               LLC(dsap=0xfe, ssap=0xfe, ctrl=0x03) / \
               CLNP() / \
               COTP(pdu_name='CR_TPDU', dref=0x0000, sref=0xc0c1, params=[
                   ('VP_CHECKSUM', 0x1234), 'VP_TPDU_SIZE', 'VP_VERSION_NR',
                   'VP_OPT_SEL', ('VP_SRC_TSAP', 'S5_PGDIR'), ('VP_DST_TSAP', 'Eop')
               ])
        pkt2 = COTP_Dot3(dst='BB:BB:BB:BB:BB:BB', src='AA:AA:AA:AA:AA:AA') / \
               LLC(dsap=0xfe, ssap=0xfe, ctrl=0x03) / \
               CLNP() / \
               COTP(pdu_name='CC_TPDU', dref=0xc0c1, sref=0x1111,
                    params=['VP_TPDU_SIZE', 'VP_OPT_SEL'])
        pkt3 = COTP_Dot3(dst='AA:AA:AA:AA:AA:AA', src='BB:BB:BB:BB:BB:BB') / \
               LLC(dsap=0xfe, ssap=0xfe, ctrl=0x03) / \
               CLNP() / \
               COTP(pdu_name='AK_TPDU', dref=0x1111, tpdunr=0, credit=1)

        pman.netif.out_queue.append_pkt(pkt1)
        pman.netif.out_queue.append_pkt(pkt2)
        pman.netif.out_queue.append_pkt(pkt3)

    def test_passive_atmt(self):
        atmt = TestPassiveATMT()
        atmt.runbg()

        pkt = COTP_Dot3(dst='08:00:06:1a:11:11', src='00:30:6e:0c:87:4e') / \
              LLC(dsap=0xfe, ssap=0xfe, ctrl=0x03) / \
              CLNP() / \
              COTP(pdu_name='CR_TPDU', dref=0x0001, sref=0xc0c1, params=[
                  ('VP_CHECKSUM', 0x1234), 'VP_TPDU_SIZE', 'VP_VERSION_NR',
                  'VP_OPT_SEL', ('VP_SRC_TSAP', 'S5_PGDIR'), ('VP_DST_TSAP', 'Eop')
              ])
        atmt.send_pkt_to_atmt(pkt)

    def test_cotp_conn_hash(self):
        conn1 = COTP_Connection(dmac='08:00:06:1a:11:11', smac='00:30:6e:0c:87:4e', dref=0x0000, sref=0x0c01)
        conn2 = COTP_Connection(dmac='00:30:6e:0c:87:4e', smac='08:00:06:1a:11:11', dref=0x0c01, sref=0x0000)
        print(conn1.get_hash())
        print(conn2.get_hash())
