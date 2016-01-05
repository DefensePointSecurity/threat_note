import datetime
import json

import libs.helpers
import requests


def farsightip(indicator):
    con = libs.helpers.db_connection()
    with con:
        cur = con.cursor()
        cur.execute("SELECT * from settings")
        settings = cur.fetchall()
        settings = settings[0]
        apikey = settings['farsightkey']
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
    con = libs.helpers.db_connection()
    with con:
        cur = con.cursor()
        cur.execute("SELECT * from settings")
        settings = cur.fetchall()
        settings = settings[0]
        apikey = settings['farsightkey']
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
