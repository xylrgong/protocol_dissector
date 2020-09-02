from protocols.cotp import *
from proxy.proxy_cotp import *
from proxy.proxy_stack_item import *


class ProxyStack(object):
    def __init__(self):
        self.st_items = []

    def process_pkt(self, pkt):
        pass

    def _add_cotp_layer(self):
        cotp_man = ProxyCOTPManager()
        self.st_items.append(cotp_man)

    def _add_s5_layer(self):
        pass


class ProxyStackS5(ProxyStack):
    def __init__(self):
        ProxyStack.__init__(self)
        self._add_cotp_layer()
        self._add_s5_layer()

    def process_pkt(self, pkt):
        cotp_man = self.st_items[0]

        if not cotp_man.process_pkt(pkt):
            return False

        if COTP_DT in pkt:
            return False  # delete me

            # s5_man = self.st_items[1]
            pass
        return True
