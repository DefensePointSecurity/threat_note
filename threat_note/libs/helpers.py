import collections
import sqlite3 as lite

from models import Setting

threat_note_types = ['IPv4', 'IPv6', 'Network', 'Domain', 'Hash', 'Entity', 'Threat Actor']

# db_connection has been replaced with sqlachmey Deprecated, will be removed.


def db_connection(db_file='threatnote.db'):
    con = lite.connect(db_file)
    con.row_factory = lite.Row
    return con


def row_to_dict(row):
    d = {}
    for column in row.__table__.columns:
        if '_id' not in column.name:
            d[column.name] = str(getattr(row, column.name))
    return d


def get_proxy():
    settings = Setting.query.filter_by(_id=1).first()
    proxies = {
        'http': settings.httpproxy,
        'https': settings.httpproxy,
    }
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


def valid_diamond_model(diamondmodel):
    if diamondmodel in ['Adversary', 'Capability', 'Infrastructure', 'Victim']:
        return True
    else:
        return False


def valid_type(tn_type):
    if tn_type in threat_note_types:
        return True
    else:
        return False
