from scapy.packet import Packet, bind_layers, Raw
from scapy.fields import *
from scapy.compat import chb
from scapy.layers.l2 import Dot3, LLC
from utils.dissect_helper import *


# CLNP is normally not implemented
class CLNP(Packet):
    name = "CLNP"
    fields_desc = [
        XByteField('Inactive subset', 0x00)
    ]


##################################################
#  COTP: Connection Oriented Transport Protocol  #
##################################################


TPDU_TYPE = (
    {
        0x10: "ED_TPDU",  # COTP, ED Expedited Data
        0x20: "EA_TPDU",  # COTP, EA Expedited Data Acknowledgement
        0x40: "UD_TPDU",  # CLTP
        0x50: "RJ_TPDU",  # COTP, RJ Reject
        0x60: "AK_TPDU",  # COTP, AK Data Acknowledgement
        0x70: "ER_TPDU",  # COTP, ER TPDU Error
        0x80: "DR_TPDU",  # COTP, DR Disconnect Request
        0xc0: "DC_TPDU",  # COTP, DC Disconnect Confirm
        0xd0: "CC_TPDU",  # COTP, CC Connect Confirm
        0xe8: "CR_TPDU",  # COTP, CR Connect Request
        0xf0: "DT_TPDU",  # COTP, DT Data
        0x00: "Unknown"
    },
    {
        "ED_TPDU": 0x10,
        "EA_TPDU": 0x20,
        "UD_TPDU": 0x40,
        "RJ_TPDU": 0x50,
        "AK_TPDU": 0x60,
        "ER_TPDU": 0x70,
        "DR_TPDU": 0x80,
        "DC_TPDU": 0xc0,
        "CC_TPDU": 0xd0,
        "CR_TPDU": 0xe8,
        "DT_TPDU": 0xf0,
        None:      0x00
    }
)

# Variant part
VP_PART = (
    {
        # param_code: (param_name, length, default_value)
        0xc0: ("VP_TPDU_SIZE",  1, 0x0a),
        0xc1: ("VP_SRC_TSAP",   8, ''),
        0xc2: ("VP_DST_TSAP",   8, ''),
        0xc3: ("VP_CHECKSUM",   2, 0x0000),
        0xc4: ("VP_VERSION_NR", 1, 0x01),
        0xc6: ("VP_OPT_SEL",    1, 0x03)
    },
    {
        "VP_TPDU_SIZE":  0xc0,
        "VP_SRC_TSAP":   0xc1,
        "VP_DST_TSAP":   0xc2,
        "VP_CHECKSUM":   0xc3,
        "VP_VERSION_NR": 0xc4,
        "VP_OPT_SEL":    0xc6
    }
)


class COTP_Base(Packet):
    name = "COTP"
    fields_desc = [
        XByteField("Length", 0x00),
        ByteEnumField("PDUType", 0x00, TPDU_TYPE[0])
    ]


class COTP_AK(Packet):
    name = "COTP_AK"
    fields_desc = [
        XShortField('Dref', 0x0000),
        XIntField("TPDUnr", 0X00000000),
        XShortField("Credit", 0x0001)
    ]


class COTP_DR(Packet):
    name = "COTP_DR"
    fields_desc = [
        XShortField('Dref', 0x0000),
        XShortField("Sref", 0X0000),
        XShortField("Credit", 0x0001),
        ByteField('Cause', 128)
    ]


class COTP_DC(Packet):
    name = "COTP_DC"
    fields_desc = [
        XShortField('Dref', 0x0000),
        XShortField("Sref", 0X0000)
    ]


class COTP_CC(Packet):
    name = "COTP_CC"
    fields_desc = [
        XShortField('Dref', 0x0000),
        XShortField("Sref", 0x0000),
        XByteField("ClassOption", 0x00)
    ]


class COTP_CR(Packet):
    name = "COTP_CR"
    fields_desc = [
        XShortField('Dref', 0x0000),
        XShortField("Sref", 0x0000),
        XByteField("ClassOption", 0x42)
    ]


class COTP_DT(Packet):
    name = "COTP_DT"
    fields_desc = [
        XShortField('Dref', 0x0000),
        FlagsField("EOT", 1, 1, ["Last Data Unit"]),
        BitField("TPDUnr", 0, 31)
    ]


class COTP_Parameter(Packet):
    name = "COTP Variant Parameter"
    fields_desc = [
        ByteEnumField("ParamCode", 0x00, VP_PART[0]),
        XByteField("ParamLength", 0x01),
        StrLenField("Parameter", None, length_from=lambda p: p.ParamLength)
    ]


bind_layers(Dot3, LLC)
bind_layers(LLC, CLNP, dsap=0xfe)
bind_layers(LLC, CLNP, ssap=0xfe)
bind_layers(CLNP, COTP_Base)
bind_layers(COTP_Base, COTP_AK, PDUType=0x60)
bind_layers(COTP_Base, COTP_DR, PDUType=0x80)
bind_layers(COTP_Base, COTP_DC, PDUType=0xc0)
bind_layers(COTP_Base, COTP_CC, PDUType=0xd0)
bind_layers(COTP_Base, COTP_CR, PDUType=0xe8)
bind_layers(COTP_Base, COTP_DT, PDUType=0xf0)


# eg: COTP(PDUType='CR_TPDU', params=[
#             ('VP_CHECKSUM', 0x1234), 'VP_TPDU_SIZE', 'VP_VERSION_NR',
#             'VP_OPT_SEL', ('VP_SRC_TSAP', 'S5_PGDIR'), ('VP_DST_TSAP', 'Eop')
#         ])
def COTP(pdu_name=None, params=[]):
    pdu_code = TPDU_TYPE[1][pdu_name]
    need_variant_part = True
    cotp_pkt = COTP_Base(PDUType=pdu_code)

    if pdu_code == 0x60:  # AK
        cotp_pkt = cotp_pkt / COTP_AK()
    elif pdu_code == 0x80:  # DR
        cotp_pkt = cotp_pkt / COTP_DR()
    elif pdu_code == 0xc0:  # DC
        cotp_pkt = cotp_pkt / COTP_DC()
    elif pdu_code == 0xd0:  # CC
        cotp_pkt = cotp_pkt / COTP_CC()
    elif pdu_code == 0xe8:  # CR
        cotp_pkt = cotp_pkt / COTP_CR()
    elif pdu_code == 0xf0:  # DT
        cotp_pkt = cotp_pkt / COTP_DT()
    else:
        need_variant_part = False
        print('TPDU类型暂不支持，输入值：{}'.format(pdu_name))

    if need_variant_part:
        for i in range(len(params)):
            param_name = params[i]
            param_value = None
            if isinstance(params[i], tuple):
                param_name = params[i][0]
                param_value = params[i][1]

            if param_name in VP_PART[1]:
                param_code = VP_PART[1][param_name]
                param_len = VP_PART[0][param_code][1]
                param_buffer = None

                if not param_value:  # fetch default value
                    param_value = VP_PART[0][param_code][2]
                if isinstance(param_value, int):
                    param_buffer = param_value.to_bytes(length=param_len, byteorder='big', signed=False)
                elif isinstance(param_value, str):
                    param_buffer = to8byte(param_value)
                else:
                    print("不支持的参数值, 参数名：{0}, 参数值：{1}".format(param_name, param_value))
                    continue

                cotp_pkt = cotp_pkt / COTP_Parameter(ParamCode=param_code, ParamLength=param_len, Parameter=param_buffer)
            else:
                print("不支持的参数, 参数名：{0}".format(param_name))
                continue
    cotp_pkt.Length = len(cotp_pkt) - 1
    return cotp_pkt


def dissect_param(buf, i):
    param_code = buf[i]
    param_len = buf[i+1]
    param_buffer = buf[i+2: i+2+param_len]
    pkt = COTP_Parameter(ParamCode=param_code, ParamLength=param_len, Parameter=param_buffer)
    return pkt, len(pkt)


def dissect_cotp(buf):
    if len(buf) < (14 + 3 + 1):
        print("不完整的COTP数据包，长度：{}".format(len(buf)))
        return
    pkt = Dot3(buf)  # result: Dot3() / LLC() / CLNP() / COTP_Base() / COTP_?() / Raw()

    if pkt.haslayer(COTP_Base) and pkt.haslayer(Raw):
        layers = pkt.layers()
        params_len = 0
        if isinstance(layers[-2], COTP_Base):  # failed to dissect COTP_?()
            return pkt

        cotp_subset_len = lengthof_fields_desc(layers[-2].fields_desc)
        params_len = pkt.Length + 1 - 2 - cotp_subset_len
        i = 14 + 3 + 1 + 2 + cotp_subset_len
        pkt = Dot3(buf[:i])
        while params_len > 0:
            param_pkt, dlength = dissect_param(buf, i)
            pkt = pkt / param_pkt
            params_len -= dlength
            i += dlength
        pkt = pkt / buf[i: ]
    return pkt
