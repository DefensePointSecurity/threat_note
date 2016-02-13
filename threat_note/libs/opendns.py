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
    #coo = inv.cooccurrences(domain)
    #rel = inv.related(domain)
    sec = inv.security(domain)
    #tag = inv.domain_tags(domain)
    rrh = inv.rr_history(domain)

    odns_data = dict()
    odns_data['ASN'] = ', '.join(['AS' + str(i) for i in rrh['features']['asns']])
    odns_data['Prefix'] = ', '.join(rrh['features']['prefixes'])
    odns_data['Country'] = ' '.join(rrh['features']['country_codes'])
    odns_data['Age'] = rrh['features']['age']
    odns_data['ASN Score'] = round(sec['asn_score'], 2)
    odns_data['Prefix Score'] = round(sec['prefix_score'], 2)
    odns_data['Category'] = ', '.join(cat[domain]['content_categories'])
    return odns_data


def ip_investigate(ip):
    inv = investigate.Investigate(get_odns_apikey())
    rrh = inv.rr_history(ip)
    latest_domains = inv.latest_domains(ip)
    odns_data = dict()
    odns_data['Record Type: ' + rrh['rrs'][0]['type']] = rrh['rrs'][0]['rr']
    odns_data['Latest Malicious'] = ', '.join(latest_domains)
    return odns_data
