import collections

def get_proxy():
    try:
        proxies = {
            #'http': mongo.db.settings.find_one()['httpproxy'],
            #'https': mongo.db.settings.find_one()['httpsproxy'],
        }
    except KeyError:
        proxies = {}
    return proxies


# Convert function
def convert(data):
    if isinstance(data, basestring):
        return str(data)
    elif isinstance(data, collections.Mapping):
        return dict(map(convert, data.iteritems()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convert, data))
    else:
        return data