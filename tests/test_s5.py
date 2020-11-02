from automata.s5.s5_client import *


TEST_IFACE = '以太网'


class TestS5(object):
    def run(self):
        # self.test_s5_operate_ap()
        self.test_s5_operate_valve()

    # ES MAC地址：00:30:6e:0c:87:4e
    # AP MAC地址：08:00:06:1a:11:11
    # valva_name支持的取值：aa101,aa102,aa103,aa104
    # op_type支持的取值: open,close
    # sref可任意取值
    '''
    功能：实现开关阀门
    交互序列由三个部分组成：
    1.建立动态连接
    2.阀门打开/关闭操作序列（a-open/a-close字段置1）
    3.阀门a-open/a-close字段重置为0的操作序列
    操作全部完成后自动断开cotp连接
    '''
    def test_s5_operate_valve(self):
        s5_obj = s5_client(dmac='08:00:06:1a:11:11', smac='00:30:6e:0c:87:4e', sref=0x0c01, iface=TEST_IFACE)
        s5_obj.do_valve(valve_name='aa101', op_type='close')

    '''
    功能：AP为停止状态时，发出启动控制器指令；AP启动状态则发出停止指令
    参数设置：AP运行状态可以在s5_server中的is_stopped以及s5_client中的is_running中更改，且服务端和客户端运行状态需保持一致（均为运行或停止）
    交互序列组成：
    1.开启AP101和停止AP101的第一次21252序列和第二次21252序列相同
    2.开启AP101的过程，还有一段额外21252交互序列
    3.每次21252序列均有cotp连接和断开的过程
    '''
    def test_s5_operate_ap(self):
        s5_obj = s5_client(dmac='08:00:06:1a:11:11', smac='00:30:6e:0c:87:4e', sref=0x0c01, iface=TEST_IFACE)
        s5_obj.do_ap()
