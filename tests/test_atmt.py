from utils.base_automaton import *


class TestATMT(BaseAutomaton):
    def __init__(self, *args, **kwargs):
        BaseAutomaton.__init__(self, *args, **kwargs)

    def construct(self):
        self.trans = [
            (s('INIT', initial=1) >> s('STATE1')) + cond(self.cond1),
            (s('STATE1') >> s('STATE2')) + cond(timeout=5),
            (s('STATE2') >> s('STATE3')) + cond(self.cond2_recv_pkt, recv_pkt=1),
            (s('STATE3') >> s('END', final=1)),
        ]

    def cond1(self):
        return True

    def cond2_recv_pkt(self, pkt):
        return True

    def action1(self, a1, a2=None):
        print(a1, a2)

    def parse_args(self, **kwargs):
        Automaton.parse_args(self, debug=0, **kwargs)