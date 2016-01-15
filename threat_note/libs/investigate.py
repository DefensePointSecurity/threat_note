import helpers
import requests


def get_odns_apikey():
    con = libs.helpers.db_connection()
    with con:
        cur = con.cursor()
        cur.execute("SELECT odnskey from settings")
        odnskey = cur.fetchall()
        odnskey = str(odnskey[0][0])
        if odnskey == '':
            odnskey = None
    return odnskey


def domain_security(enity):
    api_url = 'https://investigate.api.opendns.com/'
    api_key = get_odns_apikey()
    headers = {'Authorization': 'Bearer ' + api_key}
    domain = enity
    endpoint = 'security/name/{}.json'
    response = requests.get(api_url + endpoint.format(domain), headers=headers, proxies=libs.helpers.get_proxy()).json()
    newdict = {}
    newdict['domain'] = domain
    newdict['attack'] = response['attack']
    newdict['asn_score'] = response['asn_score']
    newdict['dga_score'] = response['dga_score']
    newdict['prefix_score'] = response['prefix_score']
    newdict['fastflux'] = response['fastflux']
    newdict['securerank2'] = response['securerank2']
    newdict['threat_type'] = response['threat_type']
    return newdict


def domain_tag(enity):
    api_url = 'https://investigate.api.opendns.com/'
    api_key = get_odns_apikey()
    headers = {'Authorization': 'Bearer ' + api_key}
    domain = enity
    endpoint = 'domains/{}/latest_tags'
    response = requests.get(api_url + endpoint.format(domain), headers=headers, proxies=libs.helpers.get_proxy()).json()
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
        response = requests.get(api_url + endpoint + enity + labels, headers=headers, proxies=libs.helpers.get_proxy()).json()
        for domain, values in response.iteritems():
            if values['status'] == -1:  # -1 if domain is malicous
                sec = domain_security(enity)
                for row in domain_tag(enity):
                    c = row.copy()
                    c.update(sec)
                return c

            elif values['status'] == 0:
                return {'Category': 'Unclassified'}
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
        response = requests.get(api_url + endpoint, headers=headers, proxies=libs.helpers.get_proxy())
        if response.text != '[]':
            results = response.json()
            for entry in results:
                mal_domains.append(entry['name'])
        else:
            mal_domains.append('None')
        return mal_domains
    else:
        return []
