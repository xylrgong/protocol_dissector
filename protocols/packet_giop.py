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


# Field 'ServiceContextList'
class ServiceContextList(Packet):
    fields_desc = [
        IntFieldB('SequenceLength', 0x0, LITTLE_ENDIAN)
    ]


class GIOP_Request_Part1(Packet):
    name = 'GIOP Request Part'
    fields_desc = [
        PacketField('GIOPHeader', GIOP_Header(), GIOP_Header),
        XIntFieldB('RequestID', 0x00000000, LITTLE_ENDIAN),
        XByteEnumField('ResponseFlags', 0x3, GIOP_RESPONSE_FLAGS),
        X3BytesField('Reserved', 0x000000),
        PadField(XShortEnumField('TargetAddress', 0x0000, TARGET_ADDRESS_VALUES), 4),  # 4字节对齐
        FieldLenIntFieldB('KeyAddressLength', 0x0, LITTLE_ENDIAN, length_of='KeyAddress'),
        PadField(StrField('KeyAddress', ''), 4),  # 4字节对齐
        FieldLenIntFieldB('OperationLength', 0x0, LITTLE_ENDIAN, length_of='RequestOperation'),
        PadField(StrField('RequestOperation', ''), 4),  # 4字节对齐
        PacketField('ServiceContextList', ServiceContextList(), ServiceContextList)
    ]


# GIOP Request
class GIOP_Request(Packet):
    name = 'GIOP Request'
    fields_desc = [
        PadField(PacketField('GIOPFixedPart', '', GIOP_Request_Part1), 8),
        XStrField('StubData', '')
    ]

    def post_build(self, pkt, pay):
        self.GIOPFixedPart.KeyAddress = self.GIOPFixedPart.KeyAddress + b'\0'
        self.GIOPFixedPart.RequestOperation = self.GIOPFixedPart.RequestOperation + b'\0'
        self.GIOPFixedPart.KeyAddressLength = len(self.GIOPFixedPart.KeyAddress)
        self.GIOPFixedPart.OperationLength = len(self.GIOPFixedPart.RequestOperation)
        return self.self_build() + pay


GIOP_REPLY_STATUS = {
    0x0: 'No Exception',
    0x1: 'User Exception',
    0x2: 'System Exception',
    0x3: 'Location Forward',
    0x4: 'Location Forward Perm',
    0x5: 'Needs Addressing Mode',
}


class GIOP_Reply_Part1(Packet):
    name = 'GIOP Reply Part'
    fields_desc = [
        PacketField('GIOPHeader', GIOP_Header(), GIOP_Header),
        XIntFieldB('RequestID', 0x00000000, LITTLE_ENDIAN),
        IntEnumField('ReplyStatus', 0x0, GIOP_REPLY_STATUS),
        PacketField('ServiceContextList', ServiceContextList(), ServiceContextList)
    ]


# GIOP Reply
class GIOP_Reply(Packet):
    name = 'GIOP Reply'
    fields_desc = [
        PadField(PacketField('GIOPFixedPart', '', GIOP_Reply_Part1), 8),
        XStrField('StubData', '\x00')
    ]


# GIOP
# @param type: GIOP_MESSAGE_TYPE, eg: 'Request'
# @param **kwargs: 协议字段, eg: RequestID=0x171534, RequestOperation='idl_rcv_rdb_receive_data'
def GIOP(type, **kwargs):
    giop = None
    # GIOP Request
    if type==GIOP_MESSAGE_TYPE[0][0x0]:
        giop = GIOP_Request()
        giop.StubData = kwargs.pop('StubData', giop.StubData)
        giop.GIOPFixedPart = GIOP_Request_Part1(**kwargs)
    # GIOP Reply
    elif type==GIOP_MESSAGE_TYPE[0][0x1]:
        giop = GIOP_Reply()
        giop.StubData = kwargs.pop('StubData', giop.StubData)
        giop.GIOPFixedPart = GIOP_Reply_Part1(**kwargs)

    giop.GIOPFixedPart.GIOPHeader.MessageType = GIOP_MESSAGE_TYPE[1][type]
    giop.GIOPFixedPart.GIOPHeader.MessageSize = len(giop) - 12
    return giop
