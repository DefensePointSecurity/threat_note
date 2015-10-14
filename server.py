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
        with con:
            cur = con.cursor()
            cur.execute("SELECT count(DISTINCT id) AS number FROM indicators")
            counts = cur.fetchall()
            cur.execute("SELECT type, COUNT(*) AS `num` FROM indicators GROUP BY type")
            types = cur.fetchall()
            cur.execute("SELECT * FROM indicators LIMIT 5")
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



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=True)
