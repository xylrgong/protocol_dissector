from scapy.packet import Packet, bind_layers, Raw, Padding
from scapy.fields import *
from scapy.compat import chb
from scapy.layers.l2 import Dot3, LLC
from utils.utils import *
import logging as log

MIN_PKT_LENGTH = 60


class COTP_Dot3(Dot3):
    def build_padding(self):
        padding_len = MIN_PKT_LENGTH - 14 - len(self.payload)
        return b'\x00' * padding_len


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
        0xd1: "CC_TPDU",  # COTP, CC Connect Confirm
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
        "CC_TPDU": 0xd1,
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


# COTP disconnect cause
COTP_CAUSE = {
    0x00: '??????????????????',
    0x01: 'TSAP??????',
    0x02: '????????????????????? TSAP',
    0x03: '????????????',
    0x80: '????????????',
    0x81: '?????????????????????????????????????????????',
    0x82: '???????????????????????????????????????????????????',
    0x83: '??????????????? NSAP ?????????????????????????????????',
    0x84: '???????????????',
    0x85: '????????????',
    0x86: '??????',
    0x87: '???????????????',
    0x88: '??????????????????????????????????????????',
    0x89: '??????',
    0x8a: '???????????????????????????'
}


class COTP_Base(Packet):
    name = "COTP"
    fields_desc = [
        XByteField("length", 0x00),
        ByteEnumField("pdutype", 0x00, TPDU_TYPE[0])
    ]


class COTP_AK(Packet):
    name = "COTP_AK"
    fields_desc = [
        XShortField('dref', 0x0000),
        XIntField("tpdunr", 0x00000000),
        XShortField("credit", 0x0000)
    ]


class COTP_DR(Packet):
    name = "COTP_DR"
    fields_desc = [
        XShortField('dref', 0x0000),
        XShortField("sref", 0X0000),
        ByteField('cause', 0x00)
    ]


class COTP_DC(Packet):
    name = "COTP_DC"
    fields_desc = [
        XShortField('dref', 0x0000),
        XShortField("sref", 0X0000)
    ]


class COTP_CC(Packet):
    name = "COTP_CC"
    fields_desc = [
        XShortField('dref', 0x0000),
        XShortField("sref", 0x0000),
        XByteField("classoption", 0x42)
    ]

# ??????????????? dref ??? CR-TPDU ?????? 0x0000???
#           sref ?????? 0 ????????????????????????????????????????????????????????????????????????
class COTP_CR(Packet):
    name = "COTP_CR"
    fields_desc = [
        XShortField('dref', 0x0000),
        XShortField("sref", 0x0000),
        XByteField("classoption", 0x42)
    ]


class COTP_DT(Packet):
    name = "COTP_DT"
    fields_desc = [
        XShortField('dref', 0x0000),
        FlagsField("EOT", 1, 1, ["Last Data Unit"]),
        BitField("tpdunr", 0, 31)
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
bind_layers(COTP_Base, COTP_AK, pdutype=0x60)
bind_layers(COTP_Base, COTP_DR, pdutype=0x80)
bind_layers(COTP_Base, COTP_DC, pdutype=0xc0)
bind_layers(COTP_Base, COTP_CC, pdutype=0xd1)
bind_layers(COTP_Base, COTP_CR, pdutype=0xe8)
bind_layers(COTP_Base, COTP_DT, pdutype=0xf0)


# eg: COTP(pdu_name='CR_TPDU', params=[
#             ('VP_CHECKSUM', 0x1234), 'VP_TPDU_SIZE', 'VP_VERSION_NR',
#             'VP_OPT_SEL', ('VP_SRC_TSAP', 'S5_PGDIR'), ('VP_DST_TSAP', 'Eop')
#         ])
def COTP(pdu_name=None, params=[], **kwargs):
    pdu_code = TPDU_TYPE[1][pdu_name]
    need_variant_part = True
    cotp_pkt = COTP_Base(pdutype=pdu_code)

    if pdu_code == 0x60:  # AK
        cotp_pkt = cotp_pkt / COTP_AK(**kwargs)
    elif pdu_code == 0x80:  # DR
        cotp_pkt = cotp_pkt / COTP_DR(**kwargs)
    elif pdu_code == 0xc0:  # DC
        cotp_pkt = cotp_pkt / COTP_DC(**kwargs)
    elif pdu_code == 0xd1:  # CC
        cotp_pkt = cotp_pkt / COTP_CC(**kwargs)
    elif pdu_code == 0xe8:  # CR
        cotp_pkt = cotp_pkt / COTP_CR(**kwargs)
    elif pdu_code == 0xf0:  # DT
        cotp_pkt = cotp_pkt / COTP_DT(**kwargs)
    else:
        need_variant_part = False
        log.info('TPDU?????????????????????????????????{}'.format(pdu_name))

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
                    log.info("?????????????????????, ????????????{0}, ????????????{1}".format(param_name, param_value))
                    continue

                cotp_pkt = cotp_pkt / COTP_Parameter(ParamCode=param_code, ParamLength=param_len, Parameter=param_buffer)
            else:
                log.info("??????????????????, ????????????{0}".format(param_name))
                continue
    cotp_pkt.length = len(cotp_pkt) - 1
    return cotp_pkt


def dissect_param(buf, i):
    param_code = buf[i]
    param_len = buf[i+1]
    param_buffer = buf[i+2: i+2+param_len]
    pkt = COTP_Parameter(ParamCode=param_code, ParamLength=param_len, Parameter=param_buffer)
    return pkt, len(pkt)


def dissect_cotp(buf):
    buf = bytes(buf)
    if len(buf) < (14 + 3 + 1):
        log.warning("????????????COTP?????????????????????{}".format(len(buf)))
        return
    pkt = Dot3(buf)  # result: Dot3() / LLC() / CLNP() / COTP_Base() / COTP_?() / Raw()
    padding_len = 0
    if pkt.haslayer(Padding):
        padding_len = len(pkt.getlayer(Padding))

    if pkt.haslayer(COTP_Base) and pkt.haslayer(Raw):
        layers = pkt.layers()
        subset_index = layers.index(COTP_Base) + 1  # index of COTP_type
        cotp_subset_len = lengthof_fields_desc(layers[subset_index].fields_desc)  # length of COTP_type()
        params_len = pkt.length + 1 - 2 - cotp_subset_len  # cotp_length_field + 1 - cotp_header_length - ...
        i = 14 + 3 + 1 + 2 + cotp_subset_len  # eth + LLC + CLNP + COTP header + ...
        pkt = Dot3(buf[:i])  # Dot3() / LLC() / CLNP() / COTP_Base() / COTP_?()
        while params_len > 0:
            param_pkt, dlength = dissect_param(buf, i)
            pkt = pkt / param_pkt
            params_len -= dlength
            i += dlength
        pkt = pkt / Raw(buf[i: len(buf)-padding_len])
        if padding_len > 0:
            pkt = pkt / Padding(buf[len(buf)-padding_len: ])
    return pkt
