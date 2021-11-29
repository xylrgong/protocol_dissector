from protocols.h1 import *
from utils.utils import *
from protocols import cotp
import json

with open('./config_s5.json','r',encoding='utf8')as fp:
    json_data = json.load(fp)

print(json_data)
s5 = COTP_Dot3(
    dst=json_data['dst'],
    src=json_data['src'],
    len=json_data['len_ether']
)/LLC(
    dsap=json_data['dsap'],
    ssap=json_data['ssap'],
    ctrl=json_data['ctrl']
)/CLNP()/COTP_DT(
    dref=json_data['dref'],
)/H1_Request_Block(
    Block_type=json_data['Block_type'],
    Block_length=json_data['Block_length'],
    Memory_type=int(json_data['Block_length'],16),
    H1_data =json_data['H1_data']
)
s5.show()