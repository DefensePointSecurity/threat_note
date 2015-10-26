import sqlite3 as lite

con = lite.connect('threatnote.db')
con.row_factory = lite.Row
with con:
	cur = con.cursor()
	cur.execute("SELECT * from settings")
	settingsvars = cur.fetchall()

print settingsvars['apikey']