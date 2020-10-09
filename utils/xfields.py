from scapy.fields import *
from scapy.utils import lhex


class FieldB(Field):
    def __init__(self, name, default, little_endian=True, fmt='H'):
        if little_endian:
            fmt = '<' + fmt
        else:
            fmt = '>' + fmt
        Field.__init__(self, name, default, fmt)


class IntFieldB(FieldB):
    def __init__(self, name, default, little_endian=True):
        FieldB.__init__(self, name, default, little_endian, fmt="I")


class XIntFieldB(IntFieldB):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))


class FieldLenIntFieldB(FieldLenField):
    def __init__(self, name, default, little_endian=True, **kwargs):
        fmt = 'I'
        if little_endian:
            fmt = '<' + fmt
        else:
            fmt = '>' + fmt
        FieldLenField.__init__(self, name, default, fmt=fmt, **kwargs)
