from server import mongo
import requests
import json
import libs.helpers

# IPv4 VirusTotal function for passive DNS
def vt_ipv4_lookup(ipv4):
    try:
        apikey = mongo.db.settings.distinct("apikey")[0]
        url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
        params = {'ip': ipv4, 'apikey': apikey}
        r = requests.get(url, params=params, verify=False, proxies=libs.helpers.get_proxy())
        j = json.loads(r.text)
        j['resolutions'] = sorted(j['resolutions'], key=lambda k: k['last_resolved'], reverse=True)
        return j
    except:
        pass


# Domain VirusTotal function for passive DNS
def vt_domain_lookup(domain):
    try:
        apikey = mongo.db.settings.distinct("apikey")[0]
        url = "https://www.virustotal.com/vtapi/v2/domain/report"
        params = {'domain': domain, 'apikey': apikey}
        r = requests.get(url, params=params, verify=False, proxies=libs.helpers.get_proxy())
        j = json.loads(r.text)
        j['resolutions'] = sorted(j['resolutions'], key=lambda k: k['last_resolved'], reverse=True)
        return j
    except:
        pass