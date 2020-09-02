from scapy.layers.l2 import Dot3, LLC
from scapy.utils import *
from protocols.cotp import *
import re


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
    return int(length)


def is_mac(m):
    return re.match('^([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}$', m) is not None


def to_hex(pkt):
    return hexstr(pkt, onlyhex=1)
