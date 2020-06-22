from utils.base_automaton import *


class TestATMT(BaseAutomaton):
    def __init__(self, *args, **kwargs):
        BaseAutomaton.__init__(self, *args, **kwargs)

    def construct(self):
        self.trans = [(s('BEGIN', initial=1) >> s('TMP')) + cond(timeout=1) + action(self.action1, a1=1, a2=2),
                      (s('TMP') >> s('TMP2')) + cond(lambda: True),
                      (s('TMP2') >> s('END', final=1)) + cond(timeout=2)]

    def action1(self, a1, a2=None):
        print(a1, a2)

    def parse_args(self, **kwargs):
        Automaton.parse_args(self, debug=0, **kwargs)