import json

import requests
from libs.models import Setting

def shodan(indicator):
    try:
        settings = Setting.query.filter_by(_id=1).first()
        apikey = settings.shodankey
        url = "https://api.shodan.io/shodan/host/"
        ip = indicator
        tempdict = {}
        r = requests.get(url + ip + "?key=" + apikey)
        shodan = json.loads(r.text)
        for i in shodan:
            if str(i) == "data":
                for v in shodan[i]:
                    for d in v:
                        if str(d) == "html":
                            pass
                        else:
                            tempdict[v['port']] = v
            if str(i) == "city" or str(i) == "region_code" or str(i) == "os" or \
                    str(i) == "isp" or str(i) == "country_name" or str(i) == "hostnames" \
                    or str(i) == "longitude" or str(i) == "latitude" or str(i) == "vulns" \
                    or str(i) == "info" or str(i) == "product" or str(i) == "ports":
                tempdict[i] = str(shodan[i])
        for i in tempdict.keys():
            if tempdict[i] is None or tempdict[i] is "None":
                tempdict.pop(i)
        return tempdict
    except:
        pass
