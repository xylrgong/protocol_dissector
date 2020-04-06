from scapy.layers.l2 import Dot3, LLC
from protocols.cotp import *


def to8byte(s):
    assert isinstance(s, str)
    if len(s) > 8:
        return s[:8]
    else:
        return s + ' ' * (8 - len(s))


def lengthof_fields_desc(fields_desc=[]):
    length = 0
    for i in range(len(fields_desc)):
        length += fields_desc[i].sz
    return length

