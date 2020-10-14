

class GIOPConfig(object):
    def __init__(self, **kwargs):
        # 网络接口
        self.iface = kwargs.pop('iface', '')
        # TCP部分
        self.sip = None  # src ip address
        self.dip = None  # src ip address
        self.sport = None  # src TCP port
        self.dport = None  # dst TCP port


