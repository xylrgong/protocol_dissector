from scapy.packet import Packet, bind_layers, Raw, Padding
from scapy.fields import *
from utils.xfields import *
from utils.utils import *
import logging as log


# 主版本号，副版本号
MAJOR_VERSION = 0x01
MINOR_VERSION = 0x02

# 字节序
LITTLE_ENDIAN = True

# 消息类型
GIOP_MESSAGE_TYPE = (
    {
        0x0: 'Request',
        0x1: 'Reply',
        0x2: 'CancelRequest',
        0x3: 'LocateRequest',
        0x4: 'LocateReply',
        0x5: 'CloseConnection',
        0x6: 'MessageError',
        0x7: 'Fragment'
    },
    {
        'Request':         0x0,
        'Reply':           0x1,
        'CancelRequest':   0x2,
        'LocateRequest':   0x3,
        'LocateReply':     0x4,
        'CloseConnection': 0x5,
        'MessageError':    0x6,
        'Fragment':        0x7
    }
)

# Message Flags
MESSAGE_FLAGS_LIST = [
    'Little Endian',
    'Fragment',
    'ZIOP Supported',
    'ZIOP Enabled',
    'f4',
    'f5',
    'f6',
    'f7'
]


# GIOP首部
class GIOP_Header(Packet):
    name = 'GIOP Header'
    fields_desc = [
        StrField('Magic', 'GIOP'),
        XByteField('MajorVersion', MAJOR_VERSION),
        XByteField('MinorVersion', MINOR_VERSION),
        FlagsField('MessageFlags', 0x01 if LITTLE_ENDIAN else 0x00, 8, MESSAGE_FLAGS_LIST),
        XByteEnumField('MessageType', 0x00, GIOP_MESSAGE_TYPE[0]),
        IntFieldB('MessageSize', 0x0, LITTLE_ENDIAN)
    ]


# GIOP Response Flags
GIOP_RESPONSE_FLAGS = {
    0x0: 'SyncScope NONE or WITH_TRANSPORT',
    0x1: 'SyncScope WITH_SERVER',
    0x3: 'SyncScope WITH_TARGET'
}

# Target Address Discriminant Values
TARGET_ADDRESS_VALUES = {
    0x00: 'KeyAddr',
    0x01: 'ProfileAddr',
    0x02: 'ReferenceAddr'
}


# Field 'ServiceContextList' in GIOP Request
class RequestServiceContextList(Packet):
    fields_desc = [
        StrField('FixedHeadString', 'ist'),
        PadField(IntFieldB('SequenceLength', 0x0, LITTLE_ENDIAN), 8)
    ]


# Field 'ServiceContextList' in GIOP Reply
class ReplyServiceContextList(Packet):
    fields_desc = [
        IntFieldB('SequenceLength', 0x0, LITTLE_ENDIAN)
    ]


# GIOP Request
class GIOP_Request(Packet):
    name = 'GIOP Request'
    fields_desc = [
        XIntFieldB('RequestID', 0x00000000, LITTLE_ENDIAN),
        XByteEnumField('ResponseFlags', 0x3, GIOP_RESPONSE_FLAGS),
        X3BytesField('Reserved', 0x000000),
        PadField(XShortEnumField('TargetAddress', 0x0000, TARGET_ADDRESS_VALUES), 4),
        FieldLenIntFieldB('KeyAddressLength', 0x0, LITTLE_ENDIAN, length_of='KeyAddress'),
        PadField(StrField('KeyAddress', ''), 4),
        FieldLenIntFieldB('OperationLength', 0x0, LITTLE_ENDIAN, length_of='RequestOperation'),
        StrField('RequestOperation', ''),
        PacketField('ServiceContextList', RequestServiceContextList(), RequestServiceContextList),
        XStrField('StubData', '')
    ]

    def post_build(self, pkt, pay):
        self.KeyAddress = self.KeyAddress + b'\0'
        self.RequestOperation = self.RequestOperation + b'\0'
        self.KeyAddressLength = len(self.KeyAddress)
        self.OperationLength = len(self.RequestOperation)
        return self.self_build() + pay


GIOP_REPLY_STATUS = {
    0x0: 'No Exception',
    0x1: 'User Exception',
    0x2: 'System Exception',
    0x3: 'Location Forward',
    0x4: 'Location Forward Perm',
    0x5: 'Needs Addressing Mode',
}


# GIOP Reply
class GIOP_Reply(Packet):
    name = 'GIOP Reply'
    fields_desc = [
        XIntFieldB('RequestID', 0x00000000, LITTLE_ENDIAN),
        IntEnumField('ReplyStatus', 0x0, GIOP_REPLY_STATUS),
        PacketField('ServiceContextList', ReplyServiceContextList(), ReplyServiceContextList),
        XStrField('StubData', '\x00')
    ]


bind_layers(GIOP_Header, GIOP_Request, MessageType=0x0)
bind_layers(GIOP_Header, GIOP_Reply, MessageType=0x1)


# GIOP
# @param type: GIOP_MESSAGE_TYPE, eg: 'Request'
# @param **kwargs: 协议字段, eg: RequestID=0x171534, RequestOperation='idl_rcv_rdb_receive_data'
def GIOP(type, **kwargs):
    # GIOP Header
    giop = GIOP_Header()
    giop.MessageType = GIOP_MESSAGE_TYPE[1][type]

    # GIOP Request
    if type==GIOP_MESSAGE_TYPE[0][0x0]:
        giop = giop / GIOP_Request(**kwargs)
    # GIOP Reply
    elif type==GIOP_MESSAGE_TYPE[0][0x1]:
        giop = giop / GIOP_Reply(**kwargs)

    giop.MessageSize = len(giop) - 12
    return giop
