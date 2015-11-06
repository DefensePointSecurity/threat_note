import requests
import json
import libs.helpers
import sqlite3 as lite
import datetime

def circlquery(indicator):
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
        r = requests.get('https://www.circl.lu/pdns/query/'+indicator, auth=(username,password), verify=False)
        to_return = []
        for l in r.text.split('\n'):
            if len(l) == 0:
                continue
            try:
                obj = json.loads(l)
            except:
                pass
            obj['time_first'] = datetime.datetime.fromtimestamp(obj['time_last'])
            obj['time_last'] = datetime.datetime.fromtimestamp(obj['time_last'])
            to_return.append(obj)    
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
        r = requests.get('https://www.circl.lu/v2pssl/query/'+indicator, auth=(username,password), verify=False)   
        return json.loads(r.text)
    except:
        pass




