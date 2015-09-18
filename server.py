#!/usr/bin/env python

# #######################################################
# threat_note v2.0                                     #
# Developed By: Brian Warehime                         #
# Defense Point Security (defpoint.com)                #
# August 24, 2015                                      #
########################################################

###########
# Imports #
###########
from flask.ext.pymongo import PyMongo
from flask import Flask, jsonify, make_response, render_template, request, url_for, redirect
from werkzeug.datastructures import ImmutableMultiDict
import json
import bson
import requests
import collections
from ipwhois import IPWhois
import pymongo
import whois
import re
import ast
from bson.son import SON
import csv

#################
# Configuration #
#################
app = Flask(__name__)
app.config['MONGO_HOST'] = 'localhost'
app.config['MONGO_PORT'] = 27017
app.config['MONGO_DBNAME'] = 'threatnote'

mongo = PyMongo(app, config_prefix='MONGO')


###################
# Creating routes #
###################

@app.route('/', methods=['GET'])
def home():
	try:
		networks = convert(mongo.db.network.distinct("campaign"))
		dictcount = {}
		dictlist = []
		counts = float(mongo.db.network.count())
		network = mongo.db.network.find({}).sort('_id', pymongo.DESCENDING).limit(5)
		favs = mongo.db.network.find({"favorite": "True"}).sort('_id', pymongo.DESCENDING)
		for i in networks:
			x = mongo.db.network.find({"campaign": i}).count()
			if i == "":
				dictcount["category"] = "Unknown"
				tempx = x / counts
				newtemp = tempx * 100
				dictcount["value"] = round(newtemp, 2)
			else:
				dictcount["category"] = i
				tempx = x / counts
				newtemp = tempx * 100
				dictcount["value"] = round(newtemp, 2)
			dictlist.append(dictcount.copy())
		types = convert(mongo.db.network.distinct("inputtype"))
		typedict = {}
		typelist = []
		for i in types:
			x = mongo.db.network.find({"inputtype": i}).count()
			typedict["category"] = i
			tempx = x / counts
			newtemp = tempx * 100
			typedict["value"] = x
			typelist.append(typedict.copy())
		return render_template('dashboard.html', networks=dictlist, network=network, favs=favs, typelist=typelist)
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/about', methods=['GET'])
def about():
	return render_template('about.html')


@app.route('/networks', methods=['GET'])
def networks():
	try:
		# Grab only network indicators
		network = mongo.db.network.find(
			{"$or": [{"inputtype": "IPv4"}, {"inputtype": "Network"}, {"inputtype": "IPv6"}, {"inputtype": "Domain"}]})
		return render_template('networks.html', network=network)
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/threatactors', methods=['GET'])
def threatactors():
	try:
		# Grab threat actors
		threatactors = mongo.db.network.find({"inputtype": "Threat Actor"})
		return render_template('threatactors.html', network=threatactors)
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/campaigns', methods=['GET'])
def campaigns():
	try:
		campaigns = mongo.db.network.distinct("campaign")
		# Convert campaigns into Python dictionary
		campaigns = convert(campaigns)
		campaignents = {}
		for camp in campaigns:
			camprec = mongo.db.network.find({"campaign": camp}).distinct("object")
			campaignents[camp] = camprec
		campaignents = convert(campaignents)
		return render_template('campaigns.html', network=campaigns, campaignents=campaignents)
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/campaign/<uid>/info', methods=['GET'])
def campaignsummary(uid):
	try:
		http = mongo.db.network.find_one({"object": uid})
		jsonvt = ""
		whoisdata = ""
		settingsvars = mongo.db.settings.find()
		# Run ipwhois or domainwhois based on the type of indicator
		if str(http['inputtype']) == "IPv4" or str(http['inputtype']) == "IPv6" or str(
				http['inputtype']) == "Domain" or str(http['inputtype']) == "Network":
			return redirect(url_for('objectsummary', uid=http['_id']))
		else:
			return redirect(url_for('threatactorobject', uid=http['_id']))
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/newobject', methods=['GET'])
def newobj():
	try:
		return render_template('newobject.html')
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/insert/object/', methods=['POST'])
def newobject():
	try:
		something = request.form
		imd = ImmutableMultiDict(something)
		records = convert(imd)
		newdict = {}
		for i in records:
			newdict[i] = records[i]
		# Makes sure if you submit an IPv4 indicator, it's an actual IP address.
		ipregex = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', newdict['inputobject'])
		if newdict['inputtype'] == "IPv4":
			if ipregex:
				if mongo.db.network.find({"object": newdict['inputobject']}).count() > 0:
					errormessage = "Entry already exists in database."
					return render_template('newobject.html', errormessage=errormessage, inputtype=newdict['inputtype'],
					                       inputobject=newdict['inputobject'], inputfirstseen=newdict['inputfirstseen'],
					                       inputlastseen=newdict['inputlastseen'],
					                       inputcampaign=newdict['inputcampaign'],
					                       inputcomments=newdict['inputcomments'], diamondmodel=newdict['diamondmodel'])
				else:
					newdata = {"object": newdict['inputobject'].strip(), "firstseen": newdict['inputfirstseen'],
					           "lastseen": newdict['inputlastseen'], "campaign": newdict['inputcampaign'],
					           "comments": newdict['inputcomments'], "inputtype": newdict['inputtype'],
					           "diamondmodel": newdict['diamondmodel'], "favorite": "False"}
					mongo.db.network.insert(newdata)
					network = mongo.db.network.find({
						"$or": [{"inputtype": "IPv4"}, {"inputtype": "Network"}, {"inputtype": "IPv6"},
						        {"inputtype": "Domain"}]})
					return render_template('networks.html', network=network)
			else:
				errormessage = "Not a valid IP Address."
				return render_template('newobject.html', errormessage=errormessage, inputtype=newdict['inputtype'],
				                       inputobject=newdict['inputobject'], inputfirstseen=newdict['inputfirstseen'],
				                       inputlastseen=newdict['inputlastseen'], inputcampaign=newdict['inputcampaign'],
				                       inputcomments=newdict['inputcomments'], diamondmodel=newdict['diamondmodel'])
		else:
			if mongo.db.network.find({"object": newdict['inputobject']}).count() > 0:
				errormessage = "Entry already exists in database."
				return render_template('newobject.html', errormessage=errormessage, inputtype=newdict['inputtype'],
				                       inputobject=newdict['inputobject'], inputfirstseen=newdict['inputfirstseen'],
				                       inputlastseen=newdict['inputlastseen'], inputcampaign=newdict['inputcampaign'],
				                       inputcomments=newdict['inputcomments'], diamondmodel=newdict['diamondmodel'])
			else:
				newdata = {"object": newdict['inputobject'].strip(), "firstseen": newdict['inputfirstseen'],
				           "lastseen": newdict['inputlastseen'], "campaign": newdict['inputcampaign'],
				           "comments": newdict['inputcomments'], "inputtype": newdict['inputtype'],
				           "diamondmodel": newdict['diamondmodel'], "favorite": "False"}
				mongo.db.network.insert(newdata)
				if newdata['inputtype'] == "IPv6" or newdata['inputtype'] == "Domain" or newdata[
					'inputtype'] == "Network":
					network = mongo.db.network.find({
						"$or": [{"inputtype": "IPv4"}, {"inputtype": "Network"}, {"inputtype": "IPv6"},
						        {"inputtype": "Domain"}]})
					return render_template('networks.html', network=network)
				else:
					threatactors = mongo.db.network.find({"inputtype": "Threat Actor"})
					return render_template('threatactors.html', network=threatactors)
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/edit/<uid>', methods=['POST', 'GET'])
def editobject(uid):
	try:
		http = mongo.db.network.find_one({'_id': bson.ObjectId(oid=str(uid))})
		return render_template('neweditobject.html', entry=http)
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/delete/network/<uid>', methods=['GET'])
def deletenetworkobject(uid):
	try:
		mongo.db.network.remove({'_id': bson.ObjectId(oid=str(uid))})
		network = mongo.db.network.find(
			{"$or": [{"inputtype": "IPv4"}, {"inputtype": "Network"}, {"inputtype": "IPv6"}, {"inputtype": "Domain"}]})
		return render_template('networks.html', network=network)
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/delete/threatactor/<uid>', methods=['GET'])
def deletethreatactorobject(uid):
	try:
		mongo.db.network.remove({'_id': bson.ObjectId(oid=str(uid))})
		threatactors = mongo.db.network.find({"inputtype": "Threat Actor"})
		return render_template('threatactors.html', network=threatactors)
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/update/settings/', methods=['POST'])
def updatesettings():
	try:
		something = request.form
		imd = ImmutableMultiDict(something)
		records = convert(imd)
		newdict = {}
		for i in records:
			newdict[i] = records[i]
		# Make sure we're updating the settings instead of overwriting them
		if len(convert(mongo.db.settings.distinct("apikey"))) > 0:
			if 'vtinfo' in newdict.keys():
				mongo.db.settings.update({'_id': {'$exists': True}}, {'$set': {"vtinfo": "on"}})
			else:
				mongo.db.settings.update({'_id': {'$exists': True}}, {'$set': {"vtinfo": "off"}})
			if 'whoisinfo' in newdict.keys():
				mongo.db.settings.update({'_id': {'$exists': True}}, {'$set': {"whoisinfo": "on"}})
			else:
				mongo.db.settings.update({'_id': {'$exists': True}}, {'$set': {"whoisinfo": "off"}})
			mongo.db.settings.update({'_id': {'$exists': True}}, {'$set': {'apikey': newdict['apikey']}})
			if 'odns' in newdict.keys():
				mongo.db.settings.update({'_id': {'$exists': True}}, {'$set': {"odnsinfo": "on"}})
			else:
				mongo.db.settings.update({'_id': {'$exists': True}}, {'$set': {"odnsinfo": "off"}})
			mongo.db.settings.update({'_id': {'$exists': True}}, {'$set': {'odnskey': newdict['odnskey']}})
		else:
			mongo.db.settings.insert(newdict)

		if newdict['httpproxy'] != '' or newdict['httpsproxy']:
			mongo.db.settings.update({'_id': {'$exists': True}}, {'$set': {"httpproxy": newdict['httpproxy']}})
			mongo.db.settings.update({'_id': {'$exists': True}}, {'$set': {"httpsproxy": newdict['httpsproxy']}})

		newrecords = mongo.db.settings.find_one()
		return render_template('settings.html', records=newrecords)
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/update/object/', methods=['POST'])
def updateobject():
	try:
		# Updates entry information
		something = request.form
		imd = ImmutableMultiDict(something)
		records = convert(imd)
		newdict = {}
		for i in records:
			if i == "_id":
				pass
			else:
				newdict[i] = records[i]
		mongo.db.network.update({'_id': bson.ObjectId(oid=str(records['_id']))}, {'$set': newdict})
		# Returns object information with updated values
		http = mongo.db.network.find_one({'_id': bson.ObjectId(oid=str(records['_id']))})
		jsonvt = ""
		whoisdata = ""
		settingsvars = mongo.db.settings.find_one()
		if newdict['inputtype'] == "IPv4" or newdict['inputtype'] == "IPv6":
			if settingsvars['whoisinfo'] == "on":
				whoisdata = ipwhois(str(http['object']))
			if settingsvars['vtinfo'] == "on":
				jsonvt = vt_ipv4_lookup(str(http['object']))
		elif newdict['inputtype'] == "Domain":
			if settingsvars['whoisinfo'] == "on":
				whoisdata = domainwhois(str(http['object']))
			if settingsvars['vtinfo'] == "on":
				jsonvt = vt_ipv4_lookup(str(http['object']))
		if newdict['inputtype'] == "Threat Actor":
			return render_template('threatactorobject.html', records=http, jsonvt=jsonvt, whoisdata=whoisdata,
			                       settingsvars=settingsvars)
		else:
			return render_template('networkobject.html', records=http, jsonvt=jsonvt, whoisdata=whoisdata,
			                       settingsvars=settingsvars)
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/insert/newfield/', methods=['POST'])
def insertnewfield():
	try:
		something = request.form
		imd = ImmutableMultiDict(something)
		records = convert(imd)
		newdict = {}
		#dictlist = []
		for i in records:
			if i == "inputnewfieldname":
				newdict[records[i]] = records['inputnewfieldvalue']
			elif i == "inputnewfieldvalue":
				pass
			else:
				newdict[i] = records[i]
		#dictlist.append(newdict)
		return render_template('neweditobject.html', entry=newdict)
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/network/<uid>/info', methods=['GET'])
def objectsummary(uid):
	try:
		http = mongo.db.network.find_one({'_id': bson.ObjectId(oid=str(uid))})
		jsonvt = ""
		whoisdata = ""
		odnsdata = ""
		settingsvars = mongo.db.settings.find_one()
		# Run ipwhois or domainwhois based on the type of indicator
		if str(http['inputtype']) == "IPv4" or str(http['inputtype']) == "IPv6":
			if settingsvars['vtinfo'] == "on":
				jsonvt = vt_ipv4_lookup(str(http['object']))
			if settingsvars['whoisinfo'] == "on":
				whoisdata = ipwhois(str(http['object']))
			if settingsvars['odnsinfo'] == "on":
				odnsdata = investigate_ip_query(str(http['object']))
		elif str(http['inputtype']) == "Domain":
			whoisdata = domainwhois(str(http['object']))
			jsonvt = vt_domain_lookup(str(http['object']))
		if settingsvars['whoisinfo'] == "on":
			if str(http['inputtype']) == "Domain":
				address = str(whoisdata['city']) + ", " + str(whoisdata['country'])
			else:
				address = str(whoisdata['nets'][0]['city']) + ", " + str(whoisdata['nets'][0]['country'])
		else:
			address = "Information about " + str(http['object'])
		return render_template('networkobject.html', records=http, jsonvt=jsonvt, whoisdata=whoisdata,
		                       odnsdata=odnsdata, settingsvars=settingsvars, address=address)
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/threatactors/<uid>/info', methods=['GET'])
def threatactorobject(uid):
	try:
		http = mongo.db.network.find_one({'_id': bson.ObjectId(oid=str(uid))})
		return render_template('threatactorobject.html', records=http)
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/favorite/<uid>', methods=['GET'])
def favorite(uid):
	try:
		mongo.db.network.update({'_id': bson.ObjectId(oid=str(uid))}, {'$set': {"favorite": "True"}})
		http = mongo.db.network.find_one({'_id': bson.ObjectId(oid=str(uid))})
		jsonvt = ""
		whoisdata = ""
		settingsvars = mongo.db.settings.find()
		if str(http['inputtype']) == "IPv4" or str(http['inputtype']) == "IPv6":
			jsonvt = vt_ipv4_lookup(str(http['object']))
			whoisdata = ipwhois(str(http['object']))
		elif str(http['inputtype']) == "Domain":
			whoisdata = domainwhois(str(http['object']))
			jsonvt = vt_domain_lookup(str(http['object']))
		return render_template('object.html', records=http, jsonvt=jsonvt, whoisdata=whoisdata,
		                       settingsvars=settingsvars)
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/unfavorite/<uid>', methods=['GET'])
def unfavorite(uid):
	try:
		mongo.db.network.update({'_id': bson.ObjectId(oid=str(uid))}, {'$set': {"favorite": "False"}})
		http = mongo.db.network.find_one({'_id': bson.ObjectId(oid=str(uid))})
		jsonvt = ""
		whoisdata = ""
		settingsvars = mongo.db.settings.find()
		if str(http['inputtype']) == "IPv4" or str(http['inputtype']) == "IPv6":
			jsonvt = vt_ipv4_lookup(str(http['object']))
			whoisdata = ipwhois(str(http['object']))
		elif str(http['inputtype']) == "Domain":
			whoisdata = domainwhois(str(http['object']))
			jsonvt = vt_domain_lookup(str(http['object']))
		return render_template('object.html', records=http, jsonvt=jsonvt, whoisdata=whoisdata,
		                       settingsvars=settingsvars)
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/settings', methods=['GET'])
def settings():
	try:
		records = mongo.db.settings.find_one()
		return render_template('settings.html', records=records)
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/delete', methods=['GET'])
def delete():
	try:
		collection = mongo.db['network']
		collection.drop()
		message = "Database deleted successfully."
		return render_template('settings.html', message=message)
	except Exception as e:
		return render_template('error.html', error=e)


@app.route('/download/<uid>')
def download(uid):
	http = mongo.db.network.find_one({'_id': bson.ObjectId(oid=str(uid))})
	response = make_response(str(convert(http)))
	response.headers["Content-Disposition"] = "attachment; filename=" + uid + ".txt"
	return response


@app.errorhandler(404)
def not_found(error):
	e = 'Whoops, page not found!!!..try again'
	return render_template('error.html', error=e)


# Initialize the Settings database
@app.before_first_request
def _run_on_start():
	if len(convert(mongo.db.settings.distinct("apikey"))) > 0:
		pass
	else:
		mongo.db.settings.insert(
			{'apikey': '', 'vtinfo': '', 'whoisinfo': '', 'odnskey': '', 'httpsproxy': '', 'httpproxy': ''})


####################
# Global Variables #
####################

# Total Indicator Count
@app.context_processor
def totalcount():
	return dict(totalcount=mongo.db.network.count())


# Total Network Indicators
@app.context_processor
def networkcount():
	return dict(networkcount=mongo.db.network.find({
		"$or": [{"inputtype": "IPv4"}, {"inputtype": "IPv6"}, {"inputtype": "Network"}, {"inputtype": "Domain"}]}).count())


# Total Threat Actor Indicators
@app.context_processor
def threatactorcount():
	return dict(threatactorcount=mongo.db.network.find({"inputtype": "Threat Actor"}).count())


@app.context_processor
def campaigncount():
	return dict(campaigncount=len(convert(mongo.db.network.distinct("campaign"))))


#############
# Functions #
#############

def get_proxy():
	proxies = {
	    'http': mongo.db.settings.find_one()['httpproxy'],
	    'https': mongo.db.settings.find_one()['httpsproxy'],
	}
	return proxies

# IPv4 VirusTotal function for passive DNS
def vt_ipv4_lookup(ipv4):
	try:
		apikey = mongo.db.settings.distinct("apikey")[0]
		url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
		params = {'ip': ipv4, 'apikey': apikey}
		r = requests.get(url, params=params, verify=False, proxies=get_proxy())
		j = json.loads(r.text)
		j['resolutions'] = sorted(j['resolutions'], key=lambda k: k['last_resolved'], reverse=True)
		return j
	except:
		pass


# Domain VirusTotal function for passive DNS
def vt_domain_lookup(domain):
	try:
		apikey = mongo.db.settings.distinct("apikey")[0]
		url = "https://www.virustotal.com/vtapi/v2/domain/report"
		params = {'domain': domain, 'apikey': apikey}
		r = requests.get(url, params=params, verify=False, proxies=get_proxy())
		j = json.loads(r.text)
		j['resolutions'] = sorted(j['resolutions'], key=lambda k: k['last_resolved'], reverse=True)
		return j
	except:
		pass


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


def investigate_ip_query(entity):
	try:
		api_url = 'https://investigate.api.opendns.com/'
		api_key = mongo.db.settings.distinct("odnskey")[0]
		headers = {'Authorization': 'Bearer ' + api_key}
		mal_domains = []
		ip = entity.strip()
		endpoint = 'ips/{ip}/latest_domains'.format(ip=ip)
		response = requests.get(api_url + endpoint, headers=headers, proxies=get_proxy())
		if response.text != '[]':
			results = response.json()
			for entry in results:
				mal_domains.append(entry['name'])
			return mal_domains
	except:
		pass


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


if __name__ == '__main__':
	app.run(host='0.0.0.0', port=7777, debug=True)