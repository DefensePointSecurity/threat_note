#!/usr/bin/env python

# #######################################################
# threat_note v3.0                                      #
# Developed By: Brian Warehime                          #
# Defense Point Security (defpoint.com)                 #
# October 13, 2015                                      #
#########################################################

###########
# Imports #
###########
from flask import Flask, jsonify, make_response, render_template, request, url_for, redirect
from werkzeug.datastructures import ImmutableMultiDict
import bson
import re
import ast
from bson.son import SON
import csv
import io
import sqlite3 as lite
import sys

#################
# Configuration #
#################
app = Flask(__name__)

# Importing libraries

import libs.investigate
import libs.helpers
import libs.whoisinfo
import libs.virustotal

###################
# Creating routes #
###################

@app.route('/', methods=['GET'])
def home():
    try:
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        with con:
            cur = con.cursor()
            cur.execute("SELECT count(DISTINCT id) AS number FROM indicators")
            counts = cur.fetchall()
            cur.execute("SELECT type, COUNT(*) AS `num` FROM indicators GROUP BY type")
            types = cur.fetchall()
            cur.execute("SELECT * FROM indicators ORDER BY id desc LIMIT 5")
            network = cur.fetchall()
            cur.execute("SELECT DISTINCT campaign FROM indicators")
            networks = cur.fetchall()
            cur.execute("SELECT count(DISTINCT id) AS number FROM indicators")
            counts = cur.fetchall()
            counts = counts[0][0]
            dictcount = {}
            dictlist = []
            typecount = {}
            typelist = []
            for i in networks:
                cur = con.cursor()
                cur.execute("select count(id) FROM indicators WHERE campaign = '" + str(i[0]) + "'")
                campcount = cur.fetchall()
                campcount = campcount[0][0]
                if i[0] == '':
                    dictcount["category"] = "Unknown"
                    tempx = float(campcount) / float(counts)
                    newtemp = tempx * 100
                    dictcount["value"] = round(newtemp, 2)
                else:
                    dictcount["category"] = i[0]
                    tempx = float(campcount) / float(counts)
                    newtemp = tempx * 100
                    dictcount["value"] = round(newtemp,2)
                dictlist.append(dictcount.copy())
            for i in types:
                typecount["category"] = str(i[0])
                tempx = float(i[1]) / float(counts)
                newtemp = tempx * 100
                typecount["value"] = round(newtemp,2)
                typelist.append(typecount.copy())
            favs = []
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
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        with con:
            cur = con.cursor()
            cur.execute("SELECT * FROM indicators where type='IPv4' OR type='IPv6' OR type='Domain' OR type='Network'")
            network = cur.fetchall()
        return render_template('networks.html', network=network)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/threatactors', methods=['GET'])
def threatactors():
    try:
        # Grab threat actors
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        with con:
            cur = con.cursor()
            cur.execute("SELECT * FROM indicators where type='Threat Actor'")
            threatactors = cur.fetchall()
        return render_template('threatactors.html', network=threatactors)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/victims', methods=['GET'])
def victims():
    try:
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        with con:
            cur = con.cursor()
            cur.execute("SELECT * FROM indicators where diamondmodel='Victim'")
            victims = cur.fetchall()
        return render_template('victims.html', network=victims)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/campaigns', methods=['GET'])
def campaigns():
    try:
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        camplist= []
        with con:
            cur = con.cursor()
            cur.execute("SELECT DISTINCT campaign FROM indicators")
            campaigns = cur.fetchall()
            for i in campaigns:
                if i[0] == "":
                    camplist.append("Unknown")
                else:
                    camplist.append(str(i[0]))
        campaignents = {}
        for camp in campaigns:
            if camp[0] == "":
                entlist = []
                cur = con.cursor()
                cur.execute("SELECT DISTINCT object FROM indicators WHERE length(campaign) < 1")
                camps = cur.fetchall()
                for ent in camps:
                    entlist.append(str(ent[0]))
                campaignents["Unknown"] = entlist
            else:       
                entlist = []
                cur = con.cursor()
                cur.execute("SELECT DISTINCT object FROM indicators WHERE campaign = '" + str(camp[0]) + "'")
                camps = cur.fetchall()
                for ent in camps:
                    entlist.append(str(ent[0]))
                campaignents[str(camp[0])] = entlist
        return render_template('campaigns.html', network=campaigns, campaignents=campaignents)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/campaign/<uid>/info', methods=['GET'])
def campaignsummary(uid):
    try:
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from indicators where id='" + uid + "'")
            http = cur.fetchall()
            http = http[0]
            cur.execute("SELECT * from settings")
            settingsvars = cur.fetchall()
        jsonvt = ""
        whoisdata = ""
        # Run ipwhois or domainwhois based on the type of indicator
        if str(http['type']) == "IPv4" or str(http['type']) == "IPv6" or str(
                http['type']) == "Domain" or str(http['type']) == "Network":
            return redirect(url_for('objectsummary', uid=str(http['id'])))
        else:
            return redirect(url_for('threatactorobject', uid=str(http['id']))
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
        records = libs.helpers.convert(imd)
        newdict = {}
        for i in records:
            newdict[i] = records[i]
        # Makes sure if you submit an IPv4 indicator, it's an actual IP address.
        ipregex = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', newdict['inputobject'])

       # Convert the inputobject of IP or Domain to a list for Bulk Add functionality.
        newdict['inputobject'] = newdict['inputobject'].split(',')
        for newobject in newdict['inputobject']:
            if newdict['inputtype'] == "IPv4":
                if ipregex:
                    con = lite.connect('threatnote.db')
                    con.row_factory = lite.Row
                    with con:
                        cur = con.cursor()
                        cur.execute("SELECT object from indicators WHERE object = '" + newobject + "'")
                        object = cur.fetchall()
                        if len(object) > 0:
                            errormessage = "Entry already exists in database."
                            return render_template('newobject.html', errormessage=errormessage, inputtype=newdict['inputtype'],
                                                   inputobject=newobject, inputfirstseen=newdict['inputfirstseen'],
                                                   inputlastseen=newdict['inputlastseen'],
                                                   inputcampaign=newdict['inputcampaign'],
                                                   comments=newdict['comments'], diamondmodel=newdict['diamondmodel'])
                        else:
                            newdata = {"object": newobject.strip(), "firstseen": newdict['inputfirstseen'],
                                       "lastseen": newdict['inputlastseen'], "confidence": newdict['confidence'], "campaign": newdict['inputcampaign'],
                                       "comments": newdict['comments'], "inputtype": newdict['inputtype'],
                                       "diamondmodel": newdict['diamondmodel'], "favorite": "False"}
                            cur = con.cursor()
                            cur.execute("INSERT into indicators values (")
                            network = mongo.db.network.find({
                                "$or": [{"inputtype": "IPv4"}, {"inputtype": "Network"}, {"inputtype": "IPv6"},
                                        {"inputtype": "Domain"}]})
                else:
                    errormessage = "Not a valid IP Address."
                    newobject = ', '.join(newdict['inputobject'])
                    return render_template('newobject.html', errormessage=errormessage, inputtype=newdict['inputtype'],
                                           inputobject=newobject, inputfirstseen=newdict['inputfirstseen'],
                                           inputlastseen=newdict['inputlastseen'], confidence=newdict['confidence'],inputcampaign=newdict['inputcampaign'],
                                           comments=newdict['comments'], diamondmodel=newdict['diamondmodel'])
            else:
                if mongo.db.network.find({"object": newobject}).count() > 0:
                    errormessage = "Entry already exists in database."
                    newobject = ', '.join(newdict['inputobject'])
                    return render_template('newobject.html', errormessage=errormessage, inputtype=newdict['inputtype'],
                                           inputobject=newobject, inputfirstseen=newdict['inputfirstseen'],
                                           inputlastseen=newdict['inputlastseen'], confidence=newdict['confidence'], inputcampaign=newdict['inputcampaign'],
                                           comments=newdict['comments'], diamondmodel=newdict['diamondmodel'])
                else:
                    # Runs when Indicators is New and ready to be added to DB.
                    newdata = {"object": newobject.strip(), "firstseen": newdict['inputfirstseen'],
                               "lastseen": newdict['inputlastseen'], "confidence": newdict['confidence'], "campaign": newdict['inputcampaign'],
                               "comments": newdict['comments'], "inputtype": newdict['inputtype'],
                               "diamondmodel": newdict['diamondmodel'], "favorite": "False"}
                    mongo.db.network.insert(newdata)
        if newdata['inputtype'] == "IPv4" or newdata['inputtype'] == "Domain" or newdata[
            'inputtype'] == "Network" or newdata['inputtype'] == "IPv6":
            network = mongo.db.network.find({
                "$or": [{"inputtype": "IPv4"}, {"inputtype": "Network"}, {"inputtype": "IPv6"},
                        {"inputtype": "Domain"}]})
            return render_template('networks.html', network=network)

        elif newdict['diamondmodel'] == "Victim":
            victims = mongo.db.network.find({"diamondmodel": "Victim"})
            return render_template('victims.html', network=victims)
        else:
            threatactors = mongo.db.network.find({"inputtype": "Threat Actor"})
            return render_template('threatactors.html', network=threatactors)
    except Exception as e:
        return render_template('error.html', error=e)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=True)
