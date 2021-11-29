from scapy.layers.l2 import *
from scapy.layers.inet import *
from scapy.packet import Packet, bind_layers, Raw, Padding
from scapy.fields import *
from utils.utils import *
import json

with open('./config_tcp.json','r',encoding='utf8')as fp:
    json_data = json.load(fp)

print(json_data)

tcp = Ether(#构造以太网头
    src=json_data['src'],#本机MAC
    dst=json_data['dst']#广播发送
)/IP(
    src=json_data['src_ip'],
    dst=json_data['dst_ip'],
    ihl=int(json_data['ihl']),
    len=int(json_data['len_ip']),
    id=int(json_data['id_ip'],16)
)/TCP(
    sport=int(json_data['sport']),
    dport=int(json_data['dport']),
    seq=int(json_data['seq']),
    ack=int(json_data['ack']),
    window=int(json_data['window'])
      )
tcp.show()