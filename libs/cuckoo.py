import libs.helpers
import requests
import sqlite3 as lite

def get_settings():
	con = lite.connect('threatnote.db')
	con.row_factory = lite.Row
	with con:
		cur = con.cursor()
		cur.execute("SELECT cuckoohost,cuckooapiport FROM settings")

	cuckoo_settings = cur.fetchall()[0]
	cuckoo_host = cuckoo_settings[0]
	cuckoo_api_port = cuckoo_settings[1]
	return cuckoo_host, cuckoo_api_port

def report_data(cuckoo_task_id):
	host, port = get_settings()
	if host:
		cuckoo_api_resource = '/tasks/report/'
		url = 'http://' + host + ':' + port + cuckoo_api_resource + cuckoo_task_id
		r = requests.get(url)
		if r.status_code == 200:
			try:
				sha1 = r.json()['target']['file']['sha1']
				task_started = r.json()['info']['started']
				#tcp_data = r.json()['network']['tcp']
				#http_data = r.json()['network']['http']
				dns_data = r.json()['network']['dns']
				host_data = r.json()['network']['hosts']

				return host_data, dns_data, sha1, task_started
			except:
				pass
	else:
		return None, None, None, None


def get_tasks():
	try:
		host, port = get_settings()
		if host:
			url = 'http://' + host + ':' + port + '/tasks/list'
			r = requests.get(url)
			if r.status_code == 200:
				tasks = {}
				for t in r.json()['tasks']:
					if 'file' in t['category']:
						tasks[t['id']] = t['added_on']
				return tasks
	except:
		pass


