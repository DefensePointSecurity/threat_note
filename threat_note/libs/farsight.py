import datetime
import json

import helpers
import requests
from models import Setting

def farsightip(indicator):
    settings = Setting.query.filter_by(_id=1).first()
    apikey = settings.farsightkey
    headers = {'X-API-Key': apikey, 'accept': 'application/json'}
    ip = requests.get("https://api.dnsdb.info/lookup/rdata/name/" + indicator, headers=headers, verify=False)
    to_return = []
    for l in ip.text.split('\n'):
        if len(l) == 0:
            continue
        try:
            obj = json.loads(l)
            obj['time_first'] = datetime.datetime.fromtimestamp(obj['time_first'])
            obj['time_last'] = datetime.datetime.fromtimestamp(obj['time_last'])
            to_return.append(obj)
        except:
            pass
    return to_return


def farsightdomain(indicator):
    settings = Setting.query.filter_by(_id=1).first()
    apikey = settings.farsightkey
    headers = {'X-API-Key': apikey, 'accept': 'application/json'}
    domain = requests.get("https://api.dnsdb.info/lookup/rrset/name/" + indicator, headers=headers, verify=False)
    to_return = []
    for l in domain.text.split('\n'):
        if len(l) == 0:
            continue
        try:
            obj = json.loads(l)
            obj['time_first'] = datetime.datetime.fromtimestamp(obj['time_first'])
            obj['time_last'] = datetime.datetime.fromtimestamp(obj['time_last'])
            to_return.append(obj)
        except:
            pass
    return to_return
