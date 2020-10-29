from automata.s5.s5_client import *


TEST_IFACE = '以太网 2'


class TestS5(object):
    def test(self):
        # self.test_s5_operate_ap()
        self.test_s5_operate_valve()

    # ES MAC地址：00:30:6e:0c:87:4e
    # AP MAC地址：08:00:06:1a:11:11
    # TODO: sref的取值，可任意取值
    # 说明交互序列的构成
    def test_s5_operate_valve(self):
        s5_obj = s5_client(dmac='08:00:06:1a:11:11', smac='00:30:6e:0c:87:4e', sref=0x0c01, iface=TEST_IFACE)
        s5_obj.do_valve(valve_name='aa101', op_type='open')

    # TODO: 接口说明
    # 说明交互序列的构成
    def test_s5_operate_ap(self):
        s5_obj = s5_client(dmac='08:00:06:1a:11:11', smac='00:30:6e:0c:87:4e', sref=0x0c01, iface=TEST_IFACE)
        s5_obj.do_ap()
