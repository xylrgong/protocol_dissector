from protocols.cotp import *
from utils.utils import to_hex
from utils.base_automaton import *


class TestPassiveATMT(BaseAutomaton):
    def __init__(self, *args, **kwargs):
        BaseAutomaton.__init__(self, *args, **kwargs)

    def construct(self):
        self.trans = [(s('BEGIN', initial=1) >> s('TMP')) + cond(timeout=1),
                      (s('TMP') >> s('TMP2')) + wait4(self._is_cr),
                      (s('TMP2') >> s('END', final=1)) + cond(timeout=2)]

    def _is_cr(self, pkt):
        print(to_hex(pkt))
        return 0
