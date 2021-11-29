import transitions
from config import *
from utils.utils import args_to_type_list

_LOGGER = logging.getLogger(transitions.__name__)
_LOGGER.setLevel(logging.WARNING)


class StateMachineBase(object):
    def __init__(self, log_func=None):
        self.transitions = []

        self.states = []
        self.initial = None
        self.machine = None
        self._log_func = log_func

        self.construct()
        self._init()

    def construct(self):
        pass

    def input(self, *args, **kwargs):
        triggers = self.machine.get_triggers(self.state)
        if len(triggers) == 0:
            self.log_stm_info(logging.WARNING, '状态机无转移分支',
                              '状态机当前状态({})无转移分支'.format(self.state))
            return

        succeed = False
        for t in triggers:
            succeed = self.trigger(t, *args, **kwargs)

            tran = self.machine.get_transitions(trigger=t)[0]
            if len(tran.conditions) > 0:
                cond_name = tran.conditions[0].func.__name__
                self.log_stm_info(logging.DEBUG, '执行转移条件',
                                  '执行转移条件({}): {}, 参数: {}, {}'.format(succeed, cond_name, args_to_type_list(args), list(kwargs)))
            if len(tran.after) > 0:
                action_name = tran.after[0].__name__
                self.log_stm_info(logging.DEBUG, '执行转移行为',
                                  '执行转移行为: {}, 参数: {}, {}'.format(action_name, args_to_type_list(args), list(kwargs)))

            if succeed:
                break

        if succeed:
            self.log_stm_info(logging.DEBUG, '状态转移', '状态转移: {}'.format(self.state))
            self._input()
        else:
            self.log_stm_info(logging.WARNING, '状态机拒绝输入',
                              '状态机当前状态({})拒绝了所有输入, 参数: {}, {}'.format(self.state, args_to_type_list(args), list(kwargs)))

    def _input(self):
        triggers = self.machine.get_triggers(self.state)
        if len(triggers) == 0:
            return

        succeed = False
        for t in triggers:
            tran = self.machine.get_transitions(trigger=t)[0]
            if len(tran.conditions) == 0:
                succeed = self.trigger(t)
                if len(tran.after) > 0:
                    action_name = tran.after[0].__name__
                    self.log_stm_info(logging.DEBUG, '执行转移行为', '执行转移行为: {}'.format(action_name))
                break

        if succeed:
            self.log_stm_info(logging.DEBUG, '状态转移', '状态转移: {}'.format(self.state))
            self._input()

    def _init(self):
        for tran in self.transitions:
            state1 = tran.state
            state2 = tran.next_state

            if not self.initial:
                self.initial = tran.initial

            if state1 not in self.states:
                self.states.append(state1)
            if state2 not in self.states:
                self.states.append(state2)

        if not self.initial:
            self.initial = self.states[0]

        if not self.machine:
            self.machine = transitions.Machine(model=self, states=self.states, initial=self.initial,
                                               auto_transitions=False)

        _triggers = []
        for tran in self.transitions:
            cond = None if not tran.condition else tran.condition.func
            act = None if not tran.action else tran.action.func

            trigger_name = '{}__{}'.format(tran.state, tran.next_state)
            t_name = trigger_name
            i = 2
            while t_name in _triggers:
                t_name = trigger_name + '_{}'.format(i)
                i += 1
            _triggers.append(t_name)

            self.machine.add_transition(
                trigger=t_name,
                source=tran.state,
                dest=tran.next_state,
                conditions=cond,
                after=act
            )

        self.log_stm_info(logging.DEBUG, '进入初始状态', '进入初始状态: {}'.format(self.state))
        self._input()

    def log_stm_info(self, level, event_type, description):
        log.log(level, description)
        if self._log_func:
            self._log_func(level, event_type, description)


class _Condition(object):
    def __init__(self, func=None):
        self.func = func


class _Action(object):
    def __init__(self, func=None):
        self.func = func


class _Transition(object):
    def __init__(self, state, initial=0):
        self.state = state
        self.next_state = None
        self.condition = None
        self.action = None
        self.initial = None if initial == 0 else state

    def __rshift__(self, other):
        assert isinstance(other, _Transition)
        self.next_state = other.state
        self.condition = other.condition
        self.action = other.action
        if not self.initial:
            self.initial = other.initial
        return self

    def __add__(self, other):
        assert isinstance(other, _Condition) or isinstance(other, _Action)
        if isinstance(other, _Condition):
            self.condition = other
        if isinstance(other, _Action):
            self.action = other
        return self


def s(state_name, initial=0):
    assert isinstance(state_name, str) and len(state_name) > 0
    return _Transition(state_name, initial)


def cond(func):
    return _Condition(func)


def action(func):
    return _Action(func)
