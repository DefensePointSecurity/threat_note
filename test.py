import sqlite3 as lite
uid = 'asdf'
con = lite.connect('threatnote.db')
con.row_factory = lite.Row
with con:
    cur = con.cursor()
    cur.execute("SELECT * from indicators where id='2'")
    http = cur.fetchall()
    http = http[0]
    print http['type']