from ipwhois import IPWhois
import whois
import json

# IPv4 Whois
def ipwhois(entity):
    obj = IPWhois(entity)
    whoisdata = obj.lookup()
    return whoisdata
    
# Domain Whois
def domainwhois(entity):
        domain = json.loads(str(whois.whois(entity)))
        for k, v in domain.iteritems():
            if type(v) == list:
                domain[k] = ', '.join(v)
        if 'city' not in domain.keys():
            domain['city'] = 'N/A'
        return domain
