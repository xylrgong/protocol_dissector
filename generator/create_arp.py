from scapy.layers.inet import *
from scapy.layers.l2 import *
from scapy.packet import Packet, bind_layers, Raw, Padding
from scapy.fields import *
from utils.utils import *
import json

with open('./config_arp.json','r',encoding='utf8')as fp:
    json_data = json.load(fp)

print(json_data)

arp = Ether(#构造以太网头
    src=json_data['src'],#本机MAC
    dst=json_data['dst']#广播发送
)/ARP(
    op=int(json_data['op']),#发送arp请求
    hwsrc=json_data['hwsrc'],#发送端以太网地址
    psrc=json_data['psrc'],#发送端ip
    hwdst=json_data['hwdst'],#目的以太网地址
    pdst=json_data['pdst']#目的ip地址
)
arp.show()