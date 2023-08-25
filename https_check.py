import socket
from contextlib import closing
import urllib3
import os
import json

def doRequest(protocol, hostname, port, path):
    """
    Check a port on the target
    """
    result = {}
    DEBUG_MODE = True
    url = f"{protocol}://{hostname}:{port}/{path}"

    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        if sock.connect_ex((hostname, int(port))) == 0:
            state = "open"
        else:
            state = "closed"

    try:
        http = urllib3.PoolManager()
        r = http.request('GET', url, timeout=5)
    except:
        print(f"[!] FATAL ERROR {hostname} - HTTP GET response error {url}")
    else:       
        # print(f"HTTP GET STATUS: {r.status}")

        # if r.status in [302]:
        #     print(f"HTTP REDIRECT >>> {r.url}")

        if 'server' in r.headers:
            server = r.headers['server']
            # print(f"HTTP GET SERVER: {r.headers['server']}")
        else:
            server = ""
        
        if 'content-type' in r.headers:
            contentType = r.headers['content-type']
            # print(f"{r.headers}")
        else:
            contentType = ""
   
    result = {
        'hostname':hostname,
        'port':port,
        'state':state,
        'url':url,
        'status':r.status,
        'server':server,
        'content-type':contentType
    }

    return json.dumps(result)

