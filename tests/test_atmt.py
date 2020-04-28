from utils.base_automaton import *


class TestATMT(BaseAutomaton):
    def __init__(self, *args, **kwargs):
        BaseAutomaton.__init__(self, *args, **kwargs)

    def BEGIN(self):
        pass

    def TMP(self):
        pass

    def TMP2(self):
        pass

    def END(self):
        pass

    def construct(self):
        self.trans = [(s(self.BEGIN, initial=1) >> s(self.TMP)) + cond(timeout=1),
                      (s(self.TMP) >> s(self.TMP2)) + cond(lambda: True),
                      (s(self.TMP2) >> s(self.END, final=1)) + cond(timeout=2)]

    def parse_args(self, **kwargs):
        Automaton.parse_args(self, debug=5, **kwargs)  # 根据本地环境修改 iface