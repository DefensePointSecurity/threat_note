import helpers
import requests

from models import Setting

def get_odns_apikey():
    settings = Setting.query.filter_by(_id=1).first()
    odnskey = settings.odnskey
    if odnskey == '':
        odnskey = None
    return odnskey

def domain_features(domain):
    api_url = 'https://investigate.api.opendns.com/'
    api_key = get_odns_apikey()
    headers = {'Authorization': 'Bearer ' + api_key}
    endpoint = 'dnsdb/name/a/{}.json'
    response = requests.get(api_url + endpoint.format(domain), headers=headers, proxies=helpers.get_proxy()).json()
    newdict = {}
    for k, v in response.iteritems():
        if 'features' in k:
            if v['asns']:
                newdict['ASN'] = v['asns']
            else:
                newdict['ASN'] = 'N/A'
            newdict['Prefix'] = ' '.join(v['prefixes'])
            newdict['Country'] = ' '.join(v['country_codes'])
            newdict['Age'] = str(v['age']) + ' days'
    return newdict


def domain_security(domain):
    api_url = 'https://investigate.api.opendns.com/'
    api_key = get_odns_apikey()
    headers = {'Authorization': 'Bearer ' + api_key}
    endpoint = 'security/name/{}.json'
    response = requests.get(api_url + endpoint.format(domain), headers=headers, proxies=helpers.get_proxy()).json()
    newdict = {}
    newdict['Domain'] = domain
    newdict['ASN Score'] = response['asn_score']
    newdict['DGA Score'] = response['dga_score']
    newdict['Prefix Score'] = response['prefix_score']
    newdict['Fast Flux'] = response['fastflux']
    newdict['Securerank2'] = response['securerank2']
    #newdict['threat_type'] = response['threat_type']
    #newdict['attack'] = response['attack']
    return newdict


def domain_tag(domain):
    api_url = 'https://investigate.api.opendns.com/'
    api_key = get_odns_apikey()
    headers = {'Authorization': 'Bearer ' + api_key}
    endpoint = 'domains/{}/latest_tags'
    response = requests.get(api_url + endpoint.format(domain), headers=headers, proxies=helpers.get_proxy()).json()
    newlist = []
    for row in response:
        newdict = {}
        begin_date = row['period']['begin']
        end_date = row['period']['end']
        newdict['begin'] = begin_date
        newdict['end'] = end_date
        if row['url'] is None:
            newdict['url'] = 'None'
        else:
            newdict['url'] = row['url']
        newdict['domain'] = domain
        newdict['category'] = row['category']
        newlist.append(newdict)
    return newlist


def domain_categories(enity):
    api_url = 'https://investigate.api.opendns.com/'
    api_key = get_odns_apikey()
    if api_key:
        headers = {'Authorization': 'Bearer ' + api_key}
        endpoint = 'domains/categorization/'
        labels = '?showLabels'
        response = requests.get(api_url + endpoint + enity + labels, headers=headers, proxies=helpers.get_proxy()).json()
        for domain, values in response.iteritems():
            if values['status'] == -1:  # -1 if domain is malicious
                data = {}
                tags = domain_tag(domain)
                sec = domain_security(domain)
                feat = domain_features(domain)
                x = data.copy()
                x.update(feat)
                x.update(sec)
                return x

            elif values['status'] == 0:
                data = {'Category': 'Unclassified'}
                sec = domain_security(domain)
                feat = domain_features(domain)
                x = data.copy()
                x.update(feat)
                x.update(sec)
                return x
            elif values['status'] == 1:
                return {'Category': ', '.join(values['content_categories'])}
    else:
        return {}


def ip_query(entity):
    api_url = 'https://investigate.api.opendns.com/'
    api_key = get_odns_apikey()
    if api_key:
        headers = {'Authorization': 'Bearer ' + api_key}
        mal_domains = []
        ip = entity.strip()
        endpoint = 'ips/{ip}/latest_domains'.format(ip=ip)
        response = requests.get(api_url + endpoint, headers=headers, proxies=helpers.get_proxy())
        if response.text != '[]':
            results = response.json()
            for entry in results:
                mal_domains.append(entry['name'])
        else:
            mal_domains.append('None')
        return mal_domains
    else:
        return []
