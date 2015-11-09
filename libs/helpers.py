import collections
import sqlite3 as lite
import os


def setup_db(db_file='threatnote.db'):
    indicator_table = '''CREATE TABLE `indicators` (`id`	INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, `object` TEXT,	`type`	TEXT,
    `firstseen`	TEXT,	`lastseen`	TEXT,	`diamondmodel`	TEXT,	`campaign`	TEXT,	`confidence`	TEXT,
    `comments`	TEXT,	`tags` TEXT,	`relationships` TEXT	);'''

    settings_table = '''CREATE TABLE `settings` (	`apikey`	TEXT,	`odnskey`	TEXT,	`vtinfo`	TEXT,
    `whoisinfo`	TEXT, `odnsinfo`	TEXT,	`httpproxy`	TEXT,	`httpsproxy`	TEXT,	`threatcrowd` TEXT,	`vtfile` TEXT,	`circlinfo`
    TEXT,	`circlusername` TEXT,	`circlpassword` TEXT,	`circlssl` TEXT,	`ptinfo` TEXT,	`ptkey` TEXT,
    cuckoohost text, cuckooapiport text);'''

    user_table = '''CREATE TABLE users (_id INTEGER NOT NULL, 	user VARCHAR, 	email VARCHAR, 	"key" VARCHAR,
                    PRIMARY KEY (_id));'''

    if not os.path.exists(db_file):
        con = lite.connect(db_file)
        with con:
            cur = con.cursor()
            for query in [indicator_table, settings_table, user_table]:
                cur.execute(query)
            cur.execute('INSERT INTO settings DEFAULT VALUES')

            # Set to blank to allow settings UI to display placeholder vaule.
            cur.execute("UPDATE settings SET cuckoohost = ''")
            cur.execute("UPDATE settings SET cuckooapiport = ''")
            cur.execute("UPDATE settings SET httpproxy = ''")
            cur.execute("UPDATE settings SET httpsproxy = ''")
            cur.execute("UPDATE settings SET odnskey = ''")
            cur.execute("UPDATE settings SET apikey = ''")
            cur.execute("UPDATE settings SET ptkey = ''")
            cur.execute("UPDATE settings SET circlusername = ''")
            cur.execute("UPDATE settings SET circlpassword = ''")


#
def db_connection(db_file='threatnote.db'):
    con = lite.connect(db_file)
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

