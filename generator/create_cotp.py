from scapy.layers.inet import *
from scapy.layers.all import *
from scapy.packet import Packet, bind_layers, Raw, Padding
from scapy.fields import *
from utils.utils import *
from protocols import cotp
import json

with open('./config_cotp.json','r',encoding='utf8')as fp:
    json_data = json.load(fp)

print(json_data)

cotp = COTP_Dot3(
    dst=json_data['dst'],
    src=json_data['src'],
    len=json_data['len_ether']
)/LLC(
    dsap=json_data['dsap'],
    ssap=json_data['ssap'],
    ctrl=json_data['ctrl']
)/CLNP()/COTP_CR(
    dref=json_data['dref'],
    sref=json_data['sref']
)
cotp.show()