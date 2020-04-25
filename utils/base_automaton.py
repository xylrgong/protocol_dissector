from scapy.automaton import *
from scapy.automaton import _ATMT_to_supersocket
from config import log
import scapy.modules.six as six


class BaseAutomaton(Automaton):
    # 需要在子类中重载
    def construct(self):
        pass

    class ATMTState(object):
        def __init__(self, func, initial=0, final=0, error=0):
            self._func = func
            self._initial = initial
            self._final = final
            self._error = error
            self.attr_name = 'STATE_{}'.format(func.__name__)
            self.next = None
            self.cond = None
            self.action = None

        def state_function(self, obj):
            @ATMT.state(initial=self._initial, final=self._final, error=self._error)
            def f(obj):
                log.debug('状态转移：{}'.format(self.attr_name))
                self._func()

            f.__name__ = "%s_wrapper" % self.attr_name
            f.atmt_state = self.attr_name
            f.atmt_origfunc.atmt_state = self.attr_name
            f.__self__ = obj
            f.__func__ = f
            return f

        def __rshift__(self, other):
            assert isinstance(other, BaseAutomaton.ATMTState)
            self.next = other
            return self

        def __add__(self, other):
            assert isinstance(other, BaseAutomaton.ATMTCondition) or isinstance(other, BaseAutomaton.ATMTAction)
            if isinstance(other, BaseAutomaton.ATMTCondition):
                self.cond = other
            if isinstance(other, BaseAutomaton.ATMTAction):
                self.action = other
            return self

    class ATMTCondition(object):
        lambda_no = 0

        # @cond_type: 0 - normal
        #             1 - receive_condition
        #             2 - timeout
        def __init__(self, func=None, cond_type=0, timeout=0, prio=0):
            self._func = func
            self._type = cond_type
            self._prio = prio
            self._timeout = timeout
            if not self._func:
                self._func = lambda: True
            if self._func.__name__ == '<lambda>':
                self._func.__name__ = 'lambda_{}'.format(self.lambda_no)
                BaseAutomaton.ATMTCondition.lambda_no += 1
            self.attr_name = 'cond_{}'.format(self._func.__name__)

        def condition_function(self, state, next_state, obj):
            cf = None
            if self._type == 0:
                @ATMT.condition(state, prio=self._prio)
                def f(obj):
                    if self._func():
                        raise next_state(obj)
                cf = f
            elif self._type == 1:
                @ATMT.receive_condition(state, prio=self._prio)
                def f(obj, pkt):
                    if self._func(pkt):
                        raise next_state(obj)
                cf = f
            elif self._type == 2:
                @ATMT.timeout(state, self._timeout)
                def f(obj):
                    if self._func():
                        raise next_state(obj)
                cf = f
            cf.__name__ = self.attr_name
            cf.atmt_condname = self.attr_name
            cf.__self__ = obj
            cf.__func__ = cf
            return cf

    class ATMTAction(object):
        def __init__(self, func, prio=0):
            self._func = func
            self._prio = prio
            self.attr_name = 'action_{}'.format(func.__name__)

        def action_function(self, condition, obj):
            @ATMT.action(condition, self._prio)
            def f(obj):
                self._func()

            f.__name__ = self.attr_name
            f.__self__ = obj
            f.__func__ = f
            return f

    def __new__(cls):
        cls = super(Automaton, cls).__new__(cls)
        if not hasattr(cls, 'trans'):
            cls.trans = []
        cls.construct()
        cls._initialize()

        # 以下部分取自 scapy.automaton.Automaton_metaclass.__new__
        # 再次初始化 decorated functions
        members = {}
        for k, v in six.iteritems(cls.__dict__):
            if k not in members:
                members[k] = v

        decorated = [v for v in six.itervalues(members)
                     if isinstance(v, types.FunctionType) and hasattr(v, "atmt_type")]  # noqa: E501

        for m in decorated:
            if m.atmt_type == ATMT.STATE:
                s = m.atmt_state
                cls.states[s] = m
                cls.recv_conditions[s] = []
                cls.ioevents[s] = []
                cls.conditions[s] = []
                cls.timeout[s] = []
                if m.atmt_initial:
                    cls.initial_states.append(m)
            elif m.atmt_type in [ATMT.CONDITION, ATMT.RECV, ATMT.TIMEOUT, ATMT.IOEVENT]:  # noqa: E501
                cls.actions[m.atmt_condname] = []

        for m in decorated:
            if m.atmt_type == ATMT.CONDITION:
                cls.conditions[m.atmt_state].append(m)
            elif m.atmt_type == ATMT.RECV:
                cls.recv_conditions[m.atmt_state].append(m)
            elif m.atmt_type == ATMT.IOEVENT:
                cls.ioevents[m.atmt_state].append(m)
                cls.ionames.append(m.atmt_ioname)
                if m.atmt_as_supersocket is not None:
                    cls.iosupersockets.append(m)
            elif m.atmt_type == ATMT.TIMEOUT:
                cls.timeout[m.atmt_state].append((m.atmt_timeout, m))
            elif m.atmt_type == ATMT.ACTION:
                for c in m.atmt_cond:
                    cls.actions[c].append(m)

        for v in six.itervalues(cls.timeout):
            v.sort(key=lambda x: x[0])
            v.append((None, None))
        for v in itertools.chain(six.itervalues(cls.conditions),
                                 six.itervalues(cls.recv_conditions),
                                 six.itervalues(cls.ioevents)):
            v.sort(key=lambda x: x.atmt_prio)
        for condname, actlst in six.iteritems(cls.actions):
            actlst.sort(key=lambda x: x.atmt_cond[condname])

        for ioev in cls.iosupersockets:
            setattr(cls, ioev.atmt_as_supersocket,
                    _ATMT_to_supersocket(ioev.atmt_as_supersocket, ioev.atmt_ioname, cls))  # noqa: E501

        return cls

    def __init__(self, *args, **kwargs):
        Automaton.__init__(self, *args, **kwargs)

    def _initialize(self):
        for atmt_state in self.trans:
            s1 = atmt_state.state_function(self)
            s2 = atmt_state.next.state_function(self)
            c = atmt_state.cond.condition_function(s1, s2, self)
            if not hasattr(self, atmt_state.attr_name):
                setattr(self, atmt_state.attr_name, s1)
            if not hasattr(self, atmt_state.next.attr_name):
                setattr(self, atmt_state.next.attr_name, s2)
            if not hasattr(self, atmt_state.cond.attr_name):
                setattr(self, atmt_state.cond.attr_name, c)
            if atmt_state.action:
                a = atmt_state.action.action_function(c, self)
                if not hasattr(self, atmt_state.action.attr_name):
                    setattr(self, atmt_state.action.attr_name, a)


def s(func, initial=0, final=0, error=0):
    assert (callable(func) and func.__name__ != '<lambda>') or isinstance(func, str)
    if isinstance(func, str):
        def f(): pass
        f.__name__ = func
        func = f
    return BaseAutomaton.ATMTState(func, initial, final, error)


def cond(func=None, timeout=0, recv_pkt=False, prio=0):
    cond_type = 0
    if recv_pkt:
        cond_type = 1
    if timeout > 0:
        cond_type = 2
    return BaseAutomaton.ATMTCondition(func, cond_type, timeout, prio)


def action(func, prio=0):
    assert callable(func) and func.__name__ != '<lambda>'
    return BaseAutomaton.ATMTAction(func, prio)


def generate_atmt(transitions=[]):
    atmt_def = type('MyATMT', (BaseAutomaton, ), {})
    atmt_def.trans = transitions
    return atmt_def()
