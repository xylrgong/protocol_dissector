import json
import time
from status_code import *
js = '{"data":[{"timeStamp":123,"item":"链接开始","desc":"尝试与xxxx进行连接。。。。"},{"timeStamp":123,"item":"链接开始","desc":"尝试与xxxx进行连接。。。。"},{"timeStamp":123,"item":"链接开始","desc":"尝试与xxxx进行连接。。。。"},{"timeStamp":123,"item":"链接开始","desc":"尝试与xxxx进行连接。。。。"}]}'

di = json.loads(js)
print(di)
print(di['data'])
print(di['data'][0])
print(di['data'][0]['timeStamp'])

res = {'data': []}
print(res)
dic = {'a': 'a'}
res['data'].append(dic)
print(res)
t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
print(t)
print(type(t))


desc1 = description

