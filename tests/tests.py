from tests.test_passive_atmt import *
from automata.cotp.cotp_config import *
from proxy.proxy_manager import *


class Test(object):
    def __init__(self):
        pass

    def run(self):
        self.test_proxy_cotp()

        print('Sleeping...')
        time.sleep(99999)

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
