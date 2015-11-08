import requests
import json
import libs.helpers
import sqlite3 as lite

def pt(indicator):
    try:
        con = libs.helpers.db_connection()
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from settings")
            settings = cur.fetchall()
            settings = settings[0]
            apikey = settings['ptkey']
        url = 'https://www.passivetotal.org/api/v1/passive'
        params = {'api_key': apikey, 'query': indicator}
        response = requests.get(url, params=params)
        json_response = json.loads(response.content)
        return json_response
    except:
        pass



