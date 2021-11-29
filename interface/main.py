import interfaces
import types
import uvicorn
from fastapi import FastAPI
from status_code import STATUS_CODE
from ifconfig import *
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

origins = [
    "http://127.0.0.1:18011",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


@app.get("/interfaces/")
async def call_method(ifname: str, value: int = -1):
    s_code, desc = -1, None
    vmap = vars(interfaces)
    if ifname in vmap \
            and isinstance(vmap[ifname], types.FunctionType) \
            and ifname[0: 3] in ('sas', 'owp', 'cfr'):
        func = vmap[ifname]
        result = func(value=value)

        if isinstance(result, tuple):
            s_code, desc = result
        else:
            s_code = result
    else:
        s_code = 40002

    if not desc:
        desc = STATUS_CODE[s_code]

    return {
        'status_code': s_code,
        'description': desc
    }


@app.get("/interface/")
async def start_method(hostname: str, devicename: str):
    desc = hostname + ' start to connect to ' + devicename
    return {
        'opration': desc
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host=SERVER_HOST_IP, port=SERVER_PORT, log_level="info")
    # vmap = vars(interfaces)
    # ifname = 'cfr_175vl_value'
    # print(vmap.keys())
    # print(ifname in vmap)
    # print(isinstance(vmap[ifname], types.FunctionType))
    # print(vmap[ifname])
    # result = vmap[ifname](value=1000)
    # print(result)