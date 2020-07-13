from scapy.packet import Packet, bind_layers, Raw
from scapy.fields import *
from scapy.compat import chb
from scapy.layers.l2 import Dot3, LLC
from utils.utils import *
import logging as log
from protocols.cotp import *

MIN_PKT_LENGTH = 60

##################################################
#           h1: Sinec H1 Protocol                #
##################################################
# 块类型
BLOCK_TYPE = (
    {
        0x01: "OPCODE_BLOCK",   # 操作码块
        0x03: "REQUEST_BLOCK",  # 请求块
        0x0f: "RESPONSE_BLOCK",  # 响应块
        0xff: "EMPTY_BLOCK",    # 空块
        0x00: "Unknown"
    },
    {
        "OPCODE_BLOCK": 0x01,
        "REQUEST_BLOCK": 0x03,
        "RESPONSE_BLOCK": 0x0f,
        "EMPTY_BLOCK": 0xff,
        None: 0x00
    }
)

# 操作码  opcode_code：opcode_name
OPCODE = (
    {
        0x03: "Write_Request",  # 写请求
        0x04: "Write_Response",  # 写响应
        0x05: "Read_Request",  # 读请求
        0x06: "Read_Response",  # 读响应
        0x0f: "NULL",  # 空操作码
        0x0d: "client",
        0x8d: "server",
        0x8e:"Unknown"

    },
    {
        "Write_Request": 0x03,
        "Write_Response": 0x04,
        "Read_Request": 0x05,
        "Read_Response": 0x06,
        "client":0x0d,
        "server": 0x8d,
        "Unknown":0x8e,
        None: 0x0f
    }
)

# 内存类型  memory_code:memory_name
MEMORY_TYPE = (
    {
        0x01: "DB",  # Variable Memory,Source/dest. data from/to data block in main memory
        0x02: "MB",  # Control Register Packed,Source/dest. data from/to data block in flag area
        0x03: "EB",  # Discrete Input Packed,Source/dest. data from/to process image of the inputs (PII)
        0x04: "AB",  # Discrete output Packed,Source/dest. data from/to process image of the outputs (PIQ)
        0x05: "PB",  # Constant,Source/dest. data from/to in I/O modules.With source data input , with dest.
        0x06: "ZB",  # Constant Memory,Data output modules
        0x07: "TB",  # Variable Memory,Source/dest. data from/to counter cells
        0x08: "BS",  # Source/dest. data from/to times cells
        0x09: "AS",  # Source/dest. data from/to memory cells addressed in absolute form
        0x0a: "DX",  # Source/dest. data from/to extended data block (for S5-135U)
        0x10: "DE",  # Source/dest. data from/to data block in external memory (only for S5-150U)
        0x11: "QB",  # Source/dest. data from/to I/O modules in the extended I/O area. for source data input module, for dest. data output module.(only with S5-150U)
        0x00: "NULL"
    },
    {
        "DB": 0x01,
        "MB": 0x02,
        "EB": 0x03,
        "AB": 0x04,
        "PB": 0x05,
        "ZB": 0x06,
        "TB": 0x07,
        "BS": 0x08,
        "AS": 0x09,
        "DX": 0x0a,
        "DE": 0x10,
        "QB": 0x11,
        None: 0x00
    }
)


class H1_Base(Packet):
    name = "H1"
    fields_desc = [
        XShortField("H1_Header", 0x5335),  # 首部标识符,固定取值0x5335，是ASCII编码的“S5”
        XByteField("Length_indicator", 0x10),
        XByteField("Block_type", 0x01),    # 块类型，传入0x01就是操作码块
        XByteField("Block_length", 0x03),  # 块长度
        ByteEnumField("Opcode", 0x00, OPCODE[0])  # 操作码
    ]


class H1_Request_Block(Packet):
    name = "H1 Request Block"
    fields_desc = [
        XByteField("Block_type", 0x03),
        XByteField("Block_length", 0x06),
        ByteEnumField("Memory_type", 0x00, MEMORY_TYPE[0]),
        XByteField("Memory_block_number", 0x00),
        XShortField("Address_within_memory_block", 0x0000),
        XShortField("Length_in_words", 0x0000),
    ]


#COTP是DT的时候，后面接的就是Request_Block
#因为目前当COTP为DT类型时，后面就会有H1_Base和H1_Request_Block，但是实际上请求块不是一定有，现在只有这一种情况，先这么写
# eg: H1(opcode_name='Write_Request', request_block=['DB',0x02,0x5304,0x0402])
def H1(opcode_name=None, request_block=[]):
    opcode_code = OPCODE[1][opcode_name]  # 参照表OPCODE，根据Write_Request(opcode_name)获取的0x03(opcode_code)
    h1_pkt = H1_Base(Opcode=opcode_code)  # 根据 操作码 构造H1_Base数据包
    if len(request_block):
        memory_name = request_block[0]
        memory_type = MEMORY_TYPE[1][memory_name]   #0x01
        memory_block_number = request_block[1]
        address_within_memory_block = request_block[2]
        length_in_words = request_block[3]
        if memory_name in MEMORY_TYPE[1]:
            h1_pkt = h1_pkt / H1_Request_Block(Memory_type=memory_type, Memory_block_number=memory_block_number,
                                               Address_within_memory_block=address_within_memory_block,
                                               Length_in_words=length_in_words)
        else:
            log.info("不支持的内存类型, 内存名：{0}".format(memory_name))
    h1_pkt.Length_indicator = len(h1_pkt)
    return h1_pkt

#定义解析h1方法
#buf即为输入的数据包，已经是转换为字节数组类型bytes的数据包，例如'\xaa\xbb\xcc\xdd\xee\xff'
#h1.opcode ==0x8e只有H1_Base没有H1_Request_Block
def dissect_h1(buf):
    pkt=dissect_cotp(buf)  # result: Dot3() / LLC() / CLNP() / COTP_Base() / COTP_?() / COTP_parameter/ Raw()
    i=14+3+1+pkt.length+1  #Dot3 LLC CLNP COTP总长度
    pkt = dissect_cotp(buf[:i])   # result: Dot3() / LLC() / CLNP() / COTP()
    buf_last=buf[i:]     #H1和S5部分
    if len(buf_last)<6:
        log.warning("不完整的h1数据包，长度：{}".format(len(buf_last)))
        return
    pkt = pkt / H1_Base(Length_indicator=buf_last[2], Block_type=buf_last[3],
                        Block_length=buf_last[4], Opcode=buf_last[5])
    i += 6
    if len(buf_last) >= 8:
        block_type=buf[i]    #即为块类型
        if block_type in BLOCK_TYPE[0]:
            block_length=buf[i+1]
            memory_type = buf[i+2]
            memory_block_number = buf[i+3]
            address_within_memory_block = buf[i+4:i+4+2]
            length_in_words = buf[i+6:i+6+2]
            pkt = pkt / H1_Request_Block(Block_type=block_type, Block_length=block_length,
                                         Memory_type=memory_type, Memory_block_number=memory_block_number,
                                         Address_within_memory_block=address_within_memory_block,
                                         Length_in_words=length_in_words)
            i+=8
    pkt = pkt / buf[i:]
    return pkt

def dissect_h1_ex(buf_last):
    i=0
    #if len(buf_last)<6:
    #    log.warning("不完整的h1数据包，长度：{}".format(len(buf_last)))
    #    return
    pkt = H1_Base(Length_indicator=buf_last[2], Block_type=buf_last[3],
                        Block_length=buf_last[4], Opcode=buf_last[5])
    i += 6
    if len(buf_last) >= 8:
        block_type=buf_last[i]   #即为块类型
        if block_type in BLOCK_TYPE[0]:
            block_length=buf_last[i+1]
            memory_type = buf_last[i+2]
            memory_block_number = buf_last[i+3]
            address_within_memory_block = buf_last[i+4:i+4+2]
            length_in_words = buf_last[i+6:i+6+2]
            pkt = pkt / H1_Request_Block(Block_type=block_type, Block_length=block_length,
                                         Memory_type=memory_type, Memory_block_number=memory_block_number,
                                         Address_within_memory_block=address_within_memory_block,
                                         Length_in_words=length_in_words)
            i+=8
    pkt = pkt / buf_last[i:]
    return pkt

















