from models import Setting


def _generate_request_instance(request_type):
    """Automatically generate a request instance to use.

    In the end, this saves us from having to load each request class in a
    explicit way. Loading via a string is helpful to reduce the code per
    call.

    :param request_type: Type of client to load
    :return: Loaded PassiveTotal client
    """
    settings = Setting.query.filter_by(_id=1).first()
    pt_username = getattr(settings, 'pt_username', None)
    pt_api_key = getattr(settings, 'pt_api_key', None)

    class_lookup = {'dns': 'DnsRequest', 'whois': 'WhoisRequest',
                    'ssl': 'SslRequest', 'enrichment': 'EnrichmentRequest',
                    'attributes': 'AttributeRequest'}
    class_name = class_lookup[request_type]
    mod = __import__('passivetotal.libs.%s' % request_type,
                     fromlist=[class_name])
    loaded = getattr(mod, class_name)
    headers = {'PT-INTEGRATION': 'ThreatNote'}
    authenticated = loaded(pt_username, pt_api_key, headers=headers)
    return authenticated


def pt_lookup(query_type, indicator):
    try:
        client = _generate_request_instance(query_type)
    except Exception as e:
        return {'error': {
            'message': 'Failed to load a PassiveTotal client',
            'developer_message': 'Ensure "passivetotal" has been installed using PIP.'
        }}

    try:
        if query_type == 'dns':
            results = client.get_passive_dns(query=indicator)
        elif query_type == 'whois':
            results = client.get_whois_details(query=indicator, compact_record=True)
            for key, value in results.get('compact', {}).iteritems():
                data = list()
                for item in value.get('values', []):
                    if not item[0]:
                        continue
                    string = "%s (%s)" % (item[0], ', '.join(item[1]))
                    data.append(string)
                results['compact'][key]['string'] = ', '.join(data)
        elif query_type == 'ssl':
            results = client.get_ssl_certificate_history(query=indicator)
        elif query_type == 'attributes':
            results = client.get_host_attribute_trackers(query=indicator)
    except Exception as e:
        return {'error': {
            'message': 'Failed to make a PassiveTotal request',
            'developer_message': 'Ensure network connectivity allows for requests to api.passivetotal.org in order to complete requests!'
        }}

    return results
