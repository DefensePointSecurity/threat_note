#!/usr/bin/env python

# #######################################################
# threat_note v3.0                                      #
# Developed By: Brian Warehime                          #
# Defense Point Security (defpoint.com)                 #
# October 26, 2015                                      #
#########################################################

###########
# Imports #
###########
from flask import Flask, jsonify, make_response, render_template, request, url_for, redirect, abort, flash
from werkzeug.datastructures import ImmutableMultiDict
import re
import ast
import csv
import io
import sqlite3 as lite
import sys
#
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, login_user, logout_user, current_user, login_required
from flask.ext.wtf import Form
from wtforms import TextField, PasswordField
from wtforms.validators import Required
import hashlib

#################
# Configuration #
#################
app = Flask(__name__)
app.config['SECRET_KEY'] = 'yek_terces'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///threatnote.db'

lm = LoginManager()
lm.init_app(app)
lm.login_view = 'login'

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    _id = db.Column('_id', db.Integer, primary_key=True, autoincrement=True)
    user = db.Column('user', db.String)
    email = db.Column('email', db.String)
    key = db.Column('key', db.String)

    def __init__(self, user, key, email):
        self.user = user.lower()
        self.key = hashlib.md5(key.encode('utf-8')).hexdigest()
        self.email = email

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self._id

class LoginForm(Form):
    user = TextField('user', validators=[Required()])
    key = PasswordField('key', validators=[Required()])

    def get_user(self):
        return db.session.query(User).filter_by(user=self.user.data.lower(), key=hashlib.md5(self.key.data.encode('utf-8')).hexdigest()).first()

class RegisterForm(Form):
    user = TextField('user', validators=[Required()])
    key = PasswordField('key', validators=[Required()])
    email = TextField('email')

@lm.user_loader
def load_user(id):
    return db.session.query(User).filter_by(_id=id).first()

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter_by(user=form.user.data.lower()).first()
        if user:
            flash('User exists.')
        else:
            user = User(form.user.data.lower(), form.key.data, form.email.data)
            db.session.add(user)
            db.session.commit()

            login_user(user)

    if current_user.is_authenticated and not current_user.is_anonymous:
        return redirect( url_for('home') )

    return render_template('register.html', form=form, title='Register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = form.get_user()
        if not user:
            flash('Invalid User or Key.')
        else:
            login_user(user)

    if current_user.is_authenticated:
        return redirect( url_for('home') )

    return render_template('login.html', form=form, title='Login')

@app.route('/logout')
def logout():
    logout_user()
    return redirect( url_for('login') )

# Importing libraries

import libs.investigate
import libs.helpers
import libs.whoisinfo
import libs.virustotal

###################
# Creating routes #
###################

@app.route('/', methods=['GET'])
@login_required
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
@login_required
def about():
    return render_template('about.html')

@app.route('/networks', methods=['GET'])
@login_required
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
@login_required
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
@login_required
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
@login_required
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

@app.route('/settings', methods=['GET'])
@login_required
def settings():
    try:
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from settings")
            records = cur.fetchall()
            records = records[0]
        return render_template('settings.html', records=records)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/campaign/<uid>/info', methods=['GET'])
@login_required
def campaignsummary(uid):
    try:
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from indicators where object='" + str(uid) + "'")
            http = cur.fetchall()
            http = http[0]
        # Run ipwhois or domainwhois based on the type of indicator
        if str(http['type']) == "IPv4" or str(http['type']) == "IPv6" or str(
                http['type']) == "Domain" or str(http['type']) == "Network":
            return redirect(url_for('objectsummary', uid=str(http['id'])))
        else:
            return redirect(url_for('threatactorobject', uid=str(http['id'])))
    except Exception as e:
       return render_template('error.html', error=e)

@app.route('/newobject', methods=['GET'])
@login_required
def newobj():
    try:
        return render_template('newobject.html')
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/insert/object/', methods=['POST'])
@login_required
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
                        cur = con.cursor()
                        cur.execute("SELECT * from indicators")
                        names = [description[0] for description in cur.description]
                        lennames = len(names) - int(9)
                        if len(object) > 0:
                            errormessage = "Entry already exists in database."
                            return render_template('newobject.html', errormessage=errormessage, inputtype=newdict['inputtype'],
                                                   inputobject=newobject, inputfirstseen=newdict['inputfirstseen'],
                                                   inputlastseen=newdict['inputlastseen'],
                                                   inputcampaign=newdict['inputcampaign'],
                                                   comments=newdict['comments'], diamondmodel=newdict['diamondmodel'])
                        else:
                            con = lite.connect('threatnote.db')
                            cur = con.cursor()
                            first = [None, newobject.strip(), newdict['inputtype'],newdict['inputfirstseen'],newdict['inputlastseen'],newdict['diamondmodel'],newdict['inputcampaign'],newdict['confidence'],newdict['comments']]
                            for t in range(0,lennames):
                                first.append("")
                            with con:
                                for t in [(first)]:
                                    cur.execute('insert into indicators values (?,?,?,?,?,?,?,?,?' + ",?"*int(lennames)+')',t)
                            con = lite.connect('threatnote.db')
                            con.row_factory = lite.Row
                            with con:
                                cur = con.cursor()
                                cur.execute("SELECT * FROM indicators where type='IPv4' OR type='IPv6' OR type='Domain' OR type='Network'")
                                network = cur.fetchall()
                else:
                    errormessage = "Not a valid IP Address."
                    newobject = ', '.join(newdict['inputobject'])
                    return render_template('newobject.html', errormessage=errormessage, inputtype=newdict['inputtype'],
                                           inputobject=newobject, inputfirstseen=newdict['inputfirstseen'],
                                           inputlastseen=newdict['inputlastseen'], confidence=newdict['confidence'],inputcampaign=newdict['inputcampaign'],
                                           comments=newdict['comments'], diamondmodel=newdict['diamondmodel'])
            else:
                con = lite.connect('threatnote.db')
                con.row_factory = lite.Row
                with con:
                    cur = con.cursor()
                    cur.execute("SELECT object from indicators WHERE object = '" + newobject + "'")
                    object = cur.fetchall()
                    cur = con.cursor()
                    cur.execute("SELECT * from indicators")
                    names = [description[0] for description in cur.description]
                    lennames = len(names) - int(9)
                    if len(object) > 0:
                        errormessage = "Entry already exists in database."
                        return render_template('newobject.html', errormessage=errormessage, inputtype=newdict['inputtype'],
                                               inputobject=newobject, inputfirstseen=newdict['inputfirstseen'],
                                               inputlastseen=newdict['inputlastseen'],
                                               inputcampaign=newdict['inputcampaign'],
                                               comments=newdict['comments'], diamondmodel=newdict['diamondmodel'])
                    else:
                        con = lite.connect('threatnote.db')
                        cur = con.cursor()
                        first = [None, newobject.strip(), newdict['inputtype'],newdict['inputfirstseen'],newdict['inputlastseen'],newdict['diamondmodel'],newdict['inputcampaign'],newdict['confidence'],newdict['comments']]
                        for t in range(0,lennames):
                            first.append("")
                        with con:
                            for t in [(first)]:
                                cur.execute('insert into indicators values (?,?,?,?,?,?,?,?,?' + ",?"*int(lennames)+')',t)
                        con = lite.connect('threatnote.db')
                        con.row_factory = lite.Row
                        with con:
                            cur = con.cursor()
                            cur.execute("SELECT * FROM indicators where type='IPv4' OR type='IPv6' OR type='Domain' OR type='Network'")
                            network = cur.fetchall()

        if newdict['inputtype'] == "IPv4" or newdict['inputtype'] == "Domain" or newdict[
            'inputtype'] == "Network" or newdict['inputtype'] == "IPv6":
            con = lite.connect('threatnote.db')
            con.row_factory = lite.Row
            with con:
                cur = con.cursor()
                cur.execute("SELECT * FROM indicators where type='IPv4' OR type='IPv6' OR type='Domain' OR type='Network'")
                network = cur.fetchall()
            return render_template('networks.html', network=network)

        elif newdict['diamondmodel'] == "Victim":
            con = lite.connect('threatnote.db')
            con.row_factory = lite.Row
            with con:
                cur = con.cursor()
                cur.execute("SELECT * FROM indicators where diamondmodel='Victim'")
                victims = cur.fetchall()
            return render_template('victims.html', network=victims)
        else:
            con = lite.connect('threatnote.db')
            con.row_factory = lite.Row
            with con:
                cur = con.cursor()
                cur.execute("SELECT * FROM indicators where type='Threat Actor'")
                threatactors = cur.fetchall()
            return render_template('threatactors.html', network=threatactors)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/edit/<uid>', methods=['POST', 'GET'])
@login_required
def editobject(uid):
    try:
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        newdict = {}
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from indicators where id='" + uid + "'")
            http = cur.fetchall()
            http = http[0]
            names = [description[0] for description in cur.description]
            for i in names:
                if i == None:
                    newdict[i] == ""
                else:
                    newdict[i] = http[i]
        return render_template('neweditobject.html', entry=newdict)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/delete/network/<uid>', methods=['GET'])
@login_required
def deletenetworkobject(uid):
    try:
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        with con:
            cur = con.cursor()
            cur.execute("DELETE FROM indicators WHERE id=?", (uid,))
            cur = con.cursor()
            cur.execute("SELECT * FROM indicators where type='IPv4' OR type='IPv6' OR type='Domain' OR type='Network'")
            network = cur.fetchall()
        return render_template('networks.html', network=network)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/delete/threatactor/<uid>', methods=['GET'])
@login_required
def deletethreatactorobject(uid):
    try:
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        with con:
            cur = con.cursor()
            cur.execute("DELETE FROM indicators WHERE id=?", (uid,))
            cur = con.cursor()
            cur.execute("SELECT * FROM indicators where type='Threat Actor'")
            network = cur.fetchall()
        return render_template('threatactors.html', network=threatactors)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/delete/victims/<uid>', methods=['GET'])
@login_required
def deletevictimobject(uid):
    try:
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        with con:
            cur = con.cursor()
            cur.execute("DELETE FROM indicators WHERE id=?", (uid,))
            cur = con.cursor()
            cur.execute("SELECT * FROM indicators where diamondmodel='victim'")
            network = cur.fetchall()
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/update/settings/', methods=['POST'])
@login_required
def updatesettings():
    try:
        something = request.form
        imd = ImmutableMultiDict(something)
        records = libs.helpers.convert(imd)
        newdict = {}
        for i in records:
            newdict[i] = records[i]
        test = newdict
        # Make sure we're updating the settings instead of overwriting them
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from settings")
            setting = cur.fetchall()
            if 'vtinfo' in newdict.keys():
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET vtinfo = 'on'")
            else:
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET vtinfo = 'off'")
            if 'whoisinfo' in newdict.keys():
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET whoisinfo = 'on'")
            else:
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET whoisinfo = 'off'")
            with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET apikey = '" + newdict['apikey'] + "'")
            if 'odnsinfo' in newdict.keys():
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET odnsinfo = 'on'")
            else:
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET odnsinfo = 'off'")
            with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET odnskey = '" + newdict['odnskey'] + "'")
            with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET httpproxy = '" + newdict['httpproxy'] + "'")
            with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET httpsproxy = '" + newdict['httpsproxy'] + "'")
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from settings")
            newrecords = cur.fetchall()
            newrecords = newrecords[0]
        return render_template('settings.html', records=newrecords, test=test)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/update/object/', methods=['POST'])
@login_required
def updateobject():
    try:
        # Updates entry information
        something = request.form
        imd = ImmutableMultiDict(something)
        records = libs.helpers.convert(imd)
        newdict = {}
        tempdict = {}
        for i in records:
            newdict[i] = records[i]
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        with con:
            for t in newdict:
                if t == "id":
                    pass
                else:
                    try:
                        cur = con.cursor()
                        cur.execute("UPDATE indicators SET " + t + "= '" + newdict[t] + "' WHERE id = '" + newdict['id'] + "'")
                    except:
                        cur = con.cursor()
                        cur.execute("ALTER TABLE indicators ADD COLUMN " + t + " TEXT DEFAULT ''")
                        cur.execute("UPDATE indicators SET " + t + "= '" + newdict[t] + "' WHERE id = '" + newdict['id'] + "'")
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from indicators where id='" + newdict['id'] + "'")
            http = cur.fetchall()
            http = http[0]
            names = [description[0] for description in cur.description]
            for i in names:
                tempdict[i] = http[i]
            cur.execute("SELECT * from settings")
            settingsvars = cur.fetchall()
            settingsvars = settingsvars[0]
        # Returns object information with updated values
        jsonvt = ""
        whoisdata = ""
        if newdict['type'] == "IPv4" or newdict['type'] == "IPv6":
            if settingsvars['whoisinfo'] == "on":
                whoisdata = libs.whoisinfo.ipwhois(str(tempdict['object']))
            if settingsvars['vtinfo'] == "on":
                jsonvt = libs.virustotal.vt_ipv4_lookup(tempdict['object'])
        elif newdict['type'] == "Domain":
            if settingsvars['whoisinfo'] == "on":
                whoisdata = libs.whoisinfo.domainwhois(str(tempdict['object']))
            if settingsvars['vtinfo'] == "on":
                jsonvt = libs.virustotal.vt_domain_lookup(str(tempdict['object']))
        if newdict['type'] == "Threat Actor":
            return render_template('threatactorobject.html', records=tempdict, jsonvt=jsonvt, whoisdata=whoisdata,
                                   settingsvars=settingsvars)
        elif newdict['diamondmodel'] == "Victim":
            return render_template('victimobject.html', records=tempdict, jsonvt=jsonvt, whoisdata=whoisdata,
                                   settingsvars=settingsvars)
        else:
            return render_template('networkobject.html', records=tempdict, jsonvt=jsonvt, whoisdata=whoisdata,
                                   settingsvars=settingsvars)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/insert/newfield/', methods=['POST'])
@login_required
def insertnewfield():
    try:
        something = request.form
        imd = ImmutableMultiDict(something)
        records = libs.helpers.convert(imd)
        newdict = {}
        for i in records:
            if i == "inputnewfieldname":
                newdict[records[i]] = records['inputnewfieldvalue']
            elif i == "inputnewfieldvalue":
                pass
            else:
                newdict[i] = records[i]
        return render_template('neweditobject.html', entry=newdict)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/network/<uid>/info', methods=['GET'])
@login_required
def objectsummary(uid):
    try:
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        newdict = {}
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from indicators where id='" + uid + "'")
            http = cur.fetchall()
            http = http[0]
            names = [description[0] for description in cur.description]
            for i in names:
                if i == None:
                    newdict[i] == ""
                else:
                    newdict[i] = str(http[i])
            cur.execute("SELECT * from settings")
            settingsvars = cur.fetchall()
            settingsvars = settingsvars[0]
        jsonvt = ""
        whoisdata = ""
        odnsdata = ""
        # Run ipwhois or domainwhois based on the type of indicator
        if str(http['type']) == "IPv4" or str(http['type']) == "IPv6":
            if settingsvars['vtinfo'] == "on":
                jsonvt = libs.virustotal.vt_ipv4_lookup(str(http['object']))
            if settingsvars['whoisinfo'] == "on":
                whoisdata = libs.whoisinfo.ipwhois(str(http['object']))
            if settingsvars['odnsinfo'] == "on":
                odnsdata = libs.investigate.ip_query(str(http['object']))
        elif str(http['type']) == "Domain":
            if settingsvars['whoisinfo'] == "on":
                whoisdata = libs.whoisinfo.domainwhois(str(http['object']))
            if settingsvars['vtinfo'] == "on":
               jsonvt = libs.virustotal.vt_domain_lookup(str(http['object']))
            if settingsvars['odnsinfo'] == "on":
                odnsdata = libs.investigate.domain_categories(str(http['object']))
        if settingsvars['whoisinfo'] == "on":
            if str(http['type']) == "Domain":
                address = str(whoisdata['city']) + ", " + str(whoisdata['country'])
            else:
                address = str(whoisdata['nets'][0]['city']) + ", " + str(whoisdata['nets'][0]['country'])
        else:
            address = "Information about " + str(http['object'])
        return render_template('networkobject.html', records=newdict, jsonvt=jsonvt, whoisdata=whoisdata,
                               odnsdata=odnsdata, settingsvars=settingsvars, address=address)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/threatactors/<uid>/info', methods=['GET'])
@login_required
def threatactorobject(uid):
    try:
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        newdict = {}
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from indicators where id='" + uid + "'")
            http = cur.fetchall()
            http = http[0]
        return render_template('threatactorobject.html', records=http)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    try:
        return render_template('profile.html')
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/victims/<uid>/info', methods=['GET'])
@login_required
def victimobject(uid):
    try:
        con = lite.connect('threatnote.db')
        con.row_factory = lite.Row
        newdict = {}
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from indicators where id='" + uid + "'")
            http = cur.fetchall()
            http = http[0]
            names = [description[0] for description in cur.description]
            for i in names:
                if i == None:
                    newdict[i] == ""
                else:
                    newdict[i] = str(http[i])
            cur.execute("SELECT * from settings")
            settingsvars = cur.fetchall()
            settingsvars = settingsvars[0]
        jsonvt = ""
        whoisdata = ""
        odnsdata = ""
        # Run ipwhois or domainwhois based on the type of indicator
        if str(http['type']) == "IPv4" or str(http['type']) == "IPv6":
            if settingsvars['vtinfo'] == "on":
                jsonvt = libs.virustotal.vt_ipv4_lookup(str(http['object']))
            if settingsvars['whoisinfo'] == "on":
                whoisdata = libs.whoisinfo.ipwhois(str(http['object']))
            if settingsvars['odnsinfo'] == "on":
                odnsdata = libs.investigate.ip_query(str(http['object']))
        elif str(http['type']) == "Domain":
            if settingsvars['whoisinfo'] == "on":
                whoisdata = libs.whoisinfo.domainwhois(str(http['object']))
            if settingsvars['vtinfo'] == "on":
                jsonvt = libs.virustotal.vt_domain_lookup(str(http['object']))
            if settingsvars['odnsinfo'] == "on":
                odnsdata = libs.investigate.domain_categories(str(http['object']))
        if settingsvars['whoisinfo'] == "on":
            if str(http['type']) == "Domain":
                address = str(whoisdata['city']) + ", " + str(whoisdata['country'])
            else:
                address = str(whoisdata['nets'][0]['city']) + ", " + str(whoisdata['nets'][0]['country'])
        else:
            address = "Information about " + str(http['object'])
        return render_template('victimobject.html', records=newdict, jsonvt=jsonvt, whoisdata=whoisdata,
                               odnsdata=odnsdata, settingsvars=settingsvars, address=address)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/download/<uid>', methods=['GET'])
@login_required
def download(uid):
    if uid == 'unknown':
        uid = ""
    file = io.BytesIO()
    fieldnames = ['id','object','type','firstseen','lastseen','diamondmodel','campaign','confidence','comments']
    con = lite.connect('threatnote.db')
    con.row_factory = lite.Row
    indlist = []
    with con:
        cur = con.cursor()
        cur.execute("SELECT * FROM indicators WHERE campaign = '" + str(uid) + "'")
        http = cur.fetchall()

    for i in http:
        indicators = []
        for item in i:
            if item == None or item == "":
                pass
            else:
                indicators.append(str(item))
        indlist.append(indicators)

    w = csv.writer(file)
    try:
        w.writerow(fieldnames)
        w.writerows(indlist)
        response = make_response(file.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=" + uid + "-campaign.csv"
        response.headers["Content-type"] = "text/csv"
        return response
    except Exception as e:
        print str(e)
        pass

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=True)
