import datetime
import json
import sqlite3 as lite

import helpers
import requests


def circlquery(indicator):
    try:
        con = libs.helpers.db_connection()
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from settings")
            settings = cur.fetchall()
            settings = settings[0]
            username = settings['circlusername']
            password = settings['circlpassword']
        r = requests.get('https://www.circl.lu/pdns/query/' + indicator, auth=(username, password), verify=False)
        to_return = []
        for l in r.text.split('\n'):
            if len(l) == 0:
                continue
            try:
                obj = json.loads(l)
            except:
                pass
            obj['time_first'] = datetime.datetime.fromtimestamp(obj['time_first'])
            obj['time_last'] = datetime.datetime.fromtimestamp(obj['time_last'])
            if len(to_return) == 0:
                return ""
            else:
                return to_return
    except:
        pass


def circlssl(indicator):
    try:
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from settings")
            settings = cur.fetchall()
            settings = settings[0]
            username = settings['circlusername']
            password = settings['circlpassword']
        r = requests.get('https://www.circl.lu/v2pssl/query/' + indicator, auth=(username, password), verify=False)
        if "certificates" in r.text:
            return json.loads(r.text)
        else:
            return ""
    except:
        pass
