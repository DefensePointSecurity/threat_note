import investigate
from models import Setting


def get_odns_apikey():
    settings = Setting.query.filter_by(_id=1).first()
    odnskey = settings.odnskey
    if odnskey == '':
        odnskey = None
    return odnskey


def domains_investigate(domain):
    inv = investigate.Investigate(get_odns_apikey())
    cat = inv.categorization(domain, labels=True)
    sec = inv.security(domain)
    rrh = inv.rr_history(domain)
    sh = inv.samples(domain, limit=10)

    # ToDo
    # tag = inv.domain_tags(domain)
    # coo = inv.cooccurrences(domain)
    # rel = inv.related(domain)

    odns_data = dict()
    try:
        odns_data['ASN'] = ', '.join(['AS' + str(i) for i in rrh['features']['asns']])
    except:
        pass
    try:
        odns_data['Prefix'] = ', '.join(rrh['features']['prefixes'])
    except:
        pass
    try:
        odns_data['Country'] = ' '.join(rrh['features']['country_codes'])
    except:
        pass
    try:
        odns_data['Age'] = rrh['features']['age']
    except:
        pass
    try:
        odns_data['ASN Score'] = round(sec['asn_score'], 2)
    except:
        pass
    try:
        odns_data['Prefix Score'] = round(sec['prefix_score'], 2)
    except:
        pass
    try:
        odns_data['Category'] = ', '.join(cat[domain]['content_categories'])
    except:
        pass
    try:
        odns_data['Security Category'] = ', '.join(cat[domain]['security_categories'])
    except:
        pass
    try:
        odns_data['Latest IP Address'] = rrh['rrs_tf'][0]['rrs'][0]['rr']
    except:
        pass
    try:
        odns_data['Associated Hashes'] = '\n'.join([h['sha256'] for h in sh['samples']])
    except:
        pass

    return odns_data


def ip_investigate(ip):
    inv = investigate.Investigate(get_odns_apikey())
    rrh = inv.rr_history(ip)
    lds = inv.latest_domains(ip)
    sh = inv.samples(ip, limit=10)
    odns_data = dict()
    odns_data['Domains'] = ', '.join([d['rr'][0:-1] for d in rrh['rrs']])
    try:
        odns_data['Associated Hashes'] = '\n'.join([h['sha256'] for h in sh['samples']])
    except:
        pass
    odns_data['Latest Malicious Domains'] = ', '.join(lds)
    return odns_data
