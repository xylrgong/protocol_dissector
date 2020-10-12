from scapy.automaton import *
from scapy.automaton import _ATMT_to_supersocket
from scapy.packet import Packet
from config import *
from utils.utils import *
from utils.packet_queue import PacketQueue
import scapy.modules.six as six


""" 
用法简介：
BaseAutomaton继承自 Scapy 的 Automaton，提供了与 Scapy 自动机略有不同的使用方式
实现自定义的自动机时，首先需要子类化 BaseAutomaton，并在子类中重载 construct 方法
contruct 方法内需要为 self.trans 属性赋值
self.trans 是一个列表，其中记录了状态转移与对应的转移条件和转移函数

contruct 的一个示例：
    def contruct(self):
        self.trans = [
            (s('起始状态') >> s('状态1')) + cond(lambda: True) + action(self.action1)
            (s('状态1') >> s('状态2')) + cond(self.condition1) + action(self.action2)
            (s('状态2') >> s('结束状态')) + cond(self.condition2) + action(self.action3)
        ]
其中，描述状态时的固定形式为 (s() >> s())，最外层的圆括号是必须的
s() 函数可以接受字符串值，用以标识一个状态名，也可以接受一个状态函数
cond() 函数接受一个函数对象，作为转移条件，条件函数必须返回一个布尔值
action() 函数接受一个函数对象，作为转移函数，在发生对应的状态转移后转移函数会被调用

除了子类化 BaseAutomaton 方式外，generate_atmt(transitions=[]) 函数可以直接返回 BaseAutomaton 的实例对象
其中 transitions 参数的形式与 self.trans 相同

Scapy的 Automaton 提供了其它 2 个可重载的函数，分别是：
    parse_args(self, **kwargs) 
    master_filter(self, pkt)
parse_args 用于在子类进行参数解析，需要注意的是子类完成解析后仍需要调用父类的 parse_args
任何未处理的参数将传递给 Automaton 的原生 socket 作为其初始参数的一部分，如果不是明确知道其含义，一般会导致报错
master_filter 用于当前自动机的全局数据包过滤，函数需要返回布尔值
"""


class BaseAutomaton(Automaton):
    # 需要在子类中重载
    def construct(self):
        pass

    # 通过pipe发送到自动机线程
    def send_pkt_to_atmt(self, pkt):
        self.in_queue.append_pkt(pkt)

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
            @ATMT.state(initial=self._initial, final=self._final, error=0)
            def f(obj_self):
                log.debug('状态转移：{:<35}自动机：{}'.format(self.attr_name, obj_self))
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
        #             3 - wait for
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

        def condition_function(self, state, next_state, obj, *args, **kwargs):
            cf = None
            # normal
            if self._type == 0:
                @ATMT.condition(state, prio=self._prio)
                def f(obj_self):
                    log.debug('条件：{:<35}自动机：{}'.format(self.attr_name, obj_self))
                    if self._func():
                        raise next_state(obj).action_parameters(*args, **kwargs)
                cf = f
            # receive pkt
            elif self._type == 1:
                @ATMT.receive_condition(state, prio=self._prio)
                def f(obj_self, pkt):
                    log.debug('条件：{:<35}自动机：{}'.format(self.attr_name, obj_self))
                    if self._func(pkt):
                        raise next_state(obj).action_parameters(*args, **kwargs)
                cf = f
            # timeout
            elif self._type == 2:
                @ATMT.timeout(state, self._timeout)
                def f(obj_self):
                    log.debug('条件：{:<35}自动机：{}'.format(self.attr_name, obj_self))
                    if self._func():
                        raise next_state(obj).action_parameters(*args, **kwargs)
                cf = f
            # wait for
            elif self._type == 3:
                @ATMT.condition(state, prio=self._prio)
                def f(obj_self):
                    while True:
                        log.debug('条件：{:<35}自动机：{}'.format(self.attr_name, obj_self))
                        pkt = obj.in_queue.recv_pkt_block(1)[0]
                        if not isinstance(pkt, Packet):
                            log.warning('Unexpected pipe data: {}'.format(pkt))
                            return  # the atmt may be stuck

                        result = self._func(pkt)
                        is_succeed = (result & 0x10) <= 0
                        pkt_action = result & 0x0f

                        if pkt_action == 0 or pkt_action == 2:  # forward
                            obj.out_queue.append_pkt(pkt)
                        elif pkt_action == 1:  # drop
                            # do nothing
                            pass
                        elif pkt_action == 3:  # re-process
                            obj.in_queue.append_pkt(pkt)

                        if is_succeed:
                            raise next_state(obj).action_parameters(*args, **kwargs)

                        if pkt_action == 2:
                            continue
                        break
                cf = f

            cf.__name__ = self.attr_name
            cf.atmt_condname = self.attr_name
            cf.__self__ = obj
            cf.__func__ = cf
            return cf

    class ATMTAction(object):
        def __init__(self, func, prio=0, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs
            self._func = func
            self._prio = prio
            self.attr_name = 'action_{}'.format(self._func.__name__)

        def action_function(self, condition, obj):
            @ATMT.action(condition, self._prio)
            def f(obj_self, *args, **kwargs):
                log.debug('行为：{:<35}自动机：{}'.format(self.attr_name, obj_self))
                self._func(*args, **kwargs)

            f.__name__ = self.attr_name
            f.__self__ = obj
            f.__func__ = f
            return f

    def __new__(cls, *args, **kwargs):
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

    def __init__(self, ll=conf.L2socket, *args, **kwargs):
        Automaton.__init__(self, ll=ll, *args, **kwargs)
        self.in_queue = PacketQueue()
        self.out_queue = PacketQueue()

    # 将 self.trans中的状态转移重写为 Automaton的状态函数、条件函数和行为函数
    def _initialize(self):
        for atmt_state in self.trans:
            s1 = atmt_state.state_function(self)
            s2 = atmt_state.next.state_function(self)
            if not atmt_state.cond:
                atmt_state.cond = cond()
            if not atmt_state.action:
                c = atmt_state.cond.condition_function(s1, s2, self)
            else:
                args = atmt_state.action.args
                kwargs = atmt_state.action.kwargs
                c = atmt_state.cond.condition_function(s1, s2, self, *args, **kwargs)

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
                else:
                    a = self.__getattribute__(a.__name__)
                    a.atmt_cond[c.atmt_condname] = c.atmt_prio


# func需要是一个非 lambda的可调用对象（表示状态函数），或字符串（表示状态名）
# initial=1时表示此状态是初始状态
# final=1时表示此状态是结束状态
# error=1时表示此状态是错误状态
def s(func, initial=0, final=0, error=0):
    assert (callable(func) and func.__name__ != '<lambda>') or isinstance(func, str)
    if isinstance(func, str):
        def f(): pass
        f.__name__ = func
        func = f
    return BaseAutomaton.ATMTState(func, initial, final, error)


# func需要是一个可调用对象（表示条件函数），func必须返回一个布尔值，当 func判断为真时，自动机进行状态转移
# timeout表示此条件是一个超时条件，在 timeout秒后，条件函数 func被调用
# recv_pkt=True表示此条件需要根据接收的数据包作判断
#     当使用 recv_pkt标志时，func需要声明为这样的形式： def func(self, pkt)
# prio表示条件函数调用的优先级，0表示最高优先级
def cond(func=None, timeout=0, recv_pkt=False, prio=0):
    cond_type = 0
    if recv_pkt:
        cond_type = 1
    if timeout > 0:
        cond_type = 2
    return BaseAutomaton.ATMTCondition(func, cond_type, timeout, prio)


# 等待外部输入的条件，func需要具有这样的签名：
# def func(self, pkt):
#     ...
#     return int_value
# 返回值含义: 表示对 pkt 的处理方式
#           0x00 - 条件成立，转发 pkt
#           0x01 - 条件成立，丢弃 pkt
#           0x10 - 条件不成立，转发 pkt
#           0x11 - 条件不成立，丢弃 pkt
#           0x12 - 条件不成立，转发 pkt，之后重新执行此条件函数
#           0x13 - 条件不成立，重处理 pkt（重新送进输入队列，作为下个 wait4 条件的输入）
def wait4(func=None, prio=0):
    cond_type = 3
    return BaseAutomaton.ATMTCondition(func, cond_type, prio=prio)


# func需要是一个非 lambda的可调用对象（表示行为函数），在发生状态转移后，进入下一个状态函数前，func会被调用
# *args, **kwargs是传递给 func 的参数
# 注意：当 func 需要接收参数时，对应的 condition 的函数名需要是唯一的，这是由于 scapy 通过 condition 向所有绑定到
#      这个条件的 action 传递参数，当存在重名的 condition 时，condition 的行为取决于最后一次绑定的 action。
#      匿名函数（lambda）不受影响。
def action(func, prio=0, *args, **kwargs):
    assert callable(func) and func.__name__ != '<lambda>'
    return BaseAutomaton.ATMTAction(func, prio, *args, **kwargs)


# 返回一个 BaseAutomaton的实例对象，使用 transitions参数描述自动机定义
def generate_atmt(transitions=[]):
    atmt_def = type('MyATMT', (BaseAutomaton, ), {})
    atmt_def.trans = transitions
    return atmt_def()
