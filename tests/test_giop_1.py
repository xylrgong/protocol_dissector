from tests.test_passive_atmt import *
from tests.test_atmt import *
from automata.cotp.cotp_config import *
from proxy.proxy_manager import *
from protocols.packet_giop import *
from utils.utils import *
from automata.giop.giop_atmt import *
from automata.giop.giop_config import *


class Test_GIOP(object):
    def test_giop_atmt(self):
        params = GIOPConfig(iface='以太网')
        atmt_obj = GIOPRequestATMT(params=params)
        atmt_obj.run()
