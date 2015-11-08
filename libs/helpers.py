import collections
import sqlite3 as lite


def db_connection():
    con = lite.connect('threatnote.db')
    con.row_factory = lite.Row
    return con


def get_proxy():
    try:
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        with con:
            cur = con.cursor()
            cur.execute("SELECT httpproxy,httpsproxy from settings")
            httpproxy = cur.fetchall()[0][0]
            #httpsproxy = cur.fetchall()[1][0]
        proxies = {
            'http': httpproxy,
            'https': httpproxy,
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

