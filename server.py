#!/usr/bin/env python

#
# threat_note v3.0                                      #
# Developed By: Brian Warehime                          #
# Defense Point Security (defpoint.com)                 #
# October 26, 2015                                      #
#


import csv
import hashlib
import io
import re
import sqlite3 as lite
import time
import urllib
import argparse

import libs.helpers
import libs.investigate
import libs.virustotal
import libs.whoisinfo
import libs.circl
import libs.passivetotal
import libs.cuckoo

from flask import Flask
from flask import flash
from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask import jsonify
from flask.ext.login import LoginManager
from flask.ext.login import current_user
from flask.ext.login import login_required
from flask.ext.login import login_user
from flask.ext.login import logout_user
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.wtf import Form

from werkzeug.datastructures import ImmutableMultiDict
from wtforms import PasswordField
from wtforms import TextField
from wtforms.validators import Required


#
# Configuration #
#
db_file = 'threatnote.db'
app = Flask(__name__)
app.config['SECRET_KEY'] = 'yek_terces'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_file

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
        user = db.session.query(User).filter_by(
            user=form.user.data.lower()).first()
        if user:
            flash('User exists.')
        else:
            user = User(form.user.data.lower(), form.key.data, form.email.data)
            db.session.add(user)
            db.session.commit()

            login_user(user)

    if current_user.is_authenticated:
        return redirect(url_for('home'))

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
        return redirect(url_for('home'))

    return render_template('login.html', form=form, title='Login')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

#
# Creating routes #
#


@app.route('/', methods=['GET'])
@login_required
def home():
    try:
        con = libs.helpers.db_connection()
        with con:
            cur = con.cursor()
            cur.execute("SELECT count(DISTINCT id) AS number FROM indicators")
            counts = cur.fetchall()
            cur.execute(
                "SELECT type, COUNT(*) AS `num` FROM indicators GROUP BY type")
            types = cur.fetchall()
            cur.execute("SELECT * FROM indicators ORDER BY id desc LIMIT 5")
            network = cur.fetchall()
            cur.execute("SELECT DISTINCT campaign FROM indicators")
            networks = cur.fetchall()
            cur.execute("SELECT count(DISTINCT id) AS number FROM indicators")
            counts = cur.fetchall()
            counts = counts[0][0]
            tags = []
            cur.execute("SELECT * FROM indicators")
            taglist = cur.fetchall()
            for tag in taglist:
                if tag['tags'] == "":
                    pass
                else:
                    fulllist = tag['tags'].split(",")
                    for tag in fulllist:
                        tags.append(tag)
            newtags = []
            for i in tags:
                  if i not in newtags:
                        newtags.append(i)
            dictcount = {}
            dictlist = []
            typecount = {}
            typelist = []
            for net in networks:
                cur = con.cursor()
                cur.execute(
                    "select count(id) FROM indicators WHERE campaign = '" + str(net[0]) + "'")
                campcount = cur.fetchall()
                campcount = campcount[0][0]
                if net[0] == '':
                    dictcount["category"] = "Unknown"
                    tempx = float(campcount) / float(counts)
                    newtemp = tempx * 100
                    dictcount["value"] = round(newtemp, 2)
                else:
                    dictcount["category"] = net[0]
                    tempx = float(campcount) / float(counts)
                    newtemp = tempx * 100
                    dictcount["value"] = round(newtemp, 2)
                dictlist.append(dictcount.copy())
            for t in types:
                typecount["category"] = str(t[0])
                tempx = float(t[1]) / float(counts)
                newtemp = tempx * 100
                typecount["value"] = round(newtemp, 2)
                typelist.append(typecount.copy())
            favs = []

            # Add Import from Cuckoo button to Dashboard page
            con = libs.helpers.db_connection()
            with con:
                cur = con.cursor()
                cur.execute("SELECT cuckoohost,cuckooapiport FROM settings")
            try:
                cuckoo_settings = cur.fetchall()[0]
                if cuckoo_settings[0]:
                    importsetting = True
                else:
                    importsetting = False
            except:
                importsetting = False

        return render_template('dashboard.html', networks=dictlist, network=network, favs=favs, typelist=typelist,
                               taglist=newtags, importsetting=importsetting)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/about', methods=['GET'])
@login_required
def about():
    return render_template('about.html')

@app.route('/tags', methods=['GET'])
@login_required
def tags():
    return render_template('tags.html')

@app.route('/networks', methods=['GET'])
@login_required
def networks():
    try:
        # Grab only network indicators
        con = libs.helpers.db_connection()
        with con:
            cur = con.cursor()
            cur.execute(
                "SELECT * FROM indicators where type='IPv4' OR type='IPv6' OR type='Domain' OR type='Network'")
            network = cur.fetchall()
        return render_template('networks.html', network=network)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/threatactors', methods=['GET'])
@login_required
def threatactors():
    try:
        # Grab threat actors
        con = libs.helpers.db_connection()
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
        con = libs.helpers.db_connection()
        with con:
            cur = con.cursor()
            cur.execute("SELECT * FROM indicators where diamondmodel='Victim'")
            victims = cur.fetchall()
        return render_template('victims.html', network=victims)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/files', methods=['GET'])
@login_required
def files():
    try:
        con = libs.helpers.db_connection()
        with con:
            cur = con.cursor()
            cur.execute("SELECT * FROM indicators where type='Hash'")
            files = cur.fetchall()
        return render_template('files.html', network=files)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/campaigns', methods=['GET'])
@login_required
def campaigns():
    try:
        con = libs.helpers.db_connection()
        camplist = []
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
                cur.execute(
                    "SELECT DISTINCT object FROM indicators WHERE length(campaign) < 1")
                camps = cur.fetchall()
                for ent in camps:
                    entlist.append(str(ent[0]))
                campaignents["Unknown"] = entlist
            else:
                entlist = []
                cur = con.cursor()
                cur.execute(
                    "SELECT DISTINCT object FROM indicators WHERE campaign = '" + str(camp[0]) + "'")
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
        con = libs.helpers.db_connection()
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
        con = libs.helpers.db_connection()
        with con:
            cur = con.cursor()
            cur.execute(
                "SELECT * from indicators where object='" + str(uid) + "'")
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
        currentdate = time.strftime("%Y-%m-%d")
        return render_template('newobject.html', currentdate=currentdate)
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

        # Import indicators from Cuckoo for the selected analysis task
        if records.has_key('type') and 'cuckoo' in records['type']:
            con = libs.helpers.db_connection()

            host_data, dns_data, sha1, firstseen = libs.cuckoo.report_data(records['cuckoo_task_id'])
            if not None in (host_data, dns_data, sha1, firstseen):
                with con:
                    cur = con.cursor()
                    for ip in host_data:
                        cur.execute('SELECT object FROM indicators WHERE object = ?', (ip,))
                        if not cur.fetchone():
                            intodb = (None, ip, 'IPv4', firstseen, '', 'Infrastructure', records['campaign'], 'Low', '',
                                      records['tags'], '')
                            with con:
                                cur.execute('insert into indicators values (?,?,?,?,?,?,?,?,?,?,?)', intodb)

                    for dns in dns_data:
                        cur.execute('SELECT object FROM indicators WHERE object = ?', (dns['request'],))
                        if not cur.fetchone():
                            intodb = (None, dns['request'], 'Domain', firstseen, '', 'Infrastructure', records['campaign'],
                                      'Low', '', records['tags'], '')
                            with con:
                                cur.execute('insert into indicators values (?,?,?,?,?,?,?,?,?,?,?)', intodb)
                    cur.execute('SELECT object FROM indicators WHERE object = ?', (sha1,))
                    if not cur.fetchone():
                        intodb = (None, sha1, 'Hash', firstseen, '', 'Capability', records['campaign'], 'Low', '',
                                  records['tags'], '')
                        with con:
                            cur.execute('insert into indicators values (?,?,?,?,?,?,?,?,?,?,?)', intodb)
                # Redirect to Dashboard after successful import
                return redirect(url_for('home'))
            else:
                errormessage = 'Task is not a file analysis'
                return redirect(url_for('import_indicators'))

        if records.has_key('inputtype'):
            # Makes sure if you submit an IPv4 indicator, it's an actual IP
            # address.
            ipregex = re.match(
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', newdict['inputobject'])
            # Convert the inputobject of IP or Domain to a list for Bulk Add
            # functionality.
            newdict['inputobject'] = newdict['inputobject'].split(',')
            for newobject in newdict['inputobject']:
                if newdict['inputtype'] == "IPv4":
                    if ipregex:
                        con = libs.helpers.db_connection()
                        with con:
                            cur = con.cursor()
                            cur.execute(
                                "SELECT object from indicators WHERE object = '" + newobject + "'")
                            object = cur.fetchall()
                            cur = con.cursor()
                            cur.execute("SELECT * from indicators")
                            names = [description[0]
                                     for description in cur.description]
                            lennames = len(names) - int(10)
                            if len(object) > 0:
                                errormessage = "Entry already exists in database."
                                return render_template(
                                    'newobject.html', errormessage=errormessage, inputtype=newdict['inputtype'],
                                    inputobject=newobject, inputfirstseen=newdict[
                                        'inputfirstseen'],
                                    inputlastseen=newdict[
                                        'inputlastseen'],
                                    inputcampaign=newdict[
                                        'inputcampaign'],
                                    comments=newdict['comments'], diamondmodel=newdict['diamondmodel'],
                                    tags=newdict['tags'])
                            else:
                                con = libs.helpers.db_connection()
                                first = [None, newobject.strip(), newdict['inputtype'], newdict['inputfirstseen'],
                                         newdict['inputlastseen'], newdict['diamondmodel'], newdict['inputcampaign'],
                                         newdict['confidence'], newdict['comments'],newdict['tags']]
                                for t in range(0, lennames):
                                    first.append("")
                                with con:
                                    for t in [(first)]:
                                        cur.execute(
                                            'insert into indicators values (?,?,?,?,?,?,?,?,?,?' + ",?" * int(lennames) + ')', t)
                                con = libs.helpers.db_connection()
                                with con:
                                    cur = con.cursor()
                                    cur.execute(
                                        "SELECT * FROM indicators where type='IPv4' OR type='IPv6' OR type='Domain' OR type='Network'")
                                    network = cur.fetchall()
                    else:
                        errormessage = "Not a valid IP Address."
                        newobject = ', '.join(newdict['inputobject'])
                        return render_template(
                            'newobject.html', errormessage=errormessage, inputtype=newdict['inputtype'],
                            inputobject=newobject, inputfirstseen=newdict[
                                'inputfirstseen'],
                            inputlastseen=newdict['inputlastseen'], confidence=newdict[
                                'confidence'], inputcampaign=newdict['inputcampaign'],
                            comments=newdict['comments'], diamondmodel=newdict['diamondmodel'],tags=newdict['tags'])
                else:
                    con = libs.helpers.db_connection()
                    with con:
                        cur = con.cursor()
                        cur.execute(
                            "SELECT object from indicators WHERE object = '" + newobject + "'")
                        object = cur.fetchall()
                        cur = con.cursor()
                        cur.execute("SELECT * from indicators")
                        names = [description[0] for description in cur.description]
                        lennames = len(names) - int(10)
                        if len(object) > 0:
                            errormessage = "Entry already exists in database."
                            return render_template(
                                'newobject.html', errormessage=errormessage, inputtype=newdict['inputtype'],
                                inputobject=newobject, inputfirstseen=newdict[
                                    'inputfirstseen'],
                                inputlastseen=newdict[
                                    'inputlastseen'],
                                inputcampaign=newdict[
                                    'inputcampaign'],
                                comments=newdict['comments'], diamondmodel=newdict['diamondmodel'],tags=newdict['tags'])
                        else:
                            con = libs.helpers.db_connection()
                            first = [None, newobject.strip(), newdict['inputtype'], newdict['inputfirstseen'], newdict[
                                'inputlastseen'], newdict['diamondmodel'], newdict['inputcampaign'], newdict['confidence'], newdict['comments'], newdict['tags']]
                            for t in range(0, lennames):
                                first.append("")
                            with con:
                                for t in [(first)]:
                                    cur.execute(
                                        'insert into indicators values (?,?,?,?,?,?,?,?,?,?' + ",?" * int(lennames) + ')', t)
                            con = libs.helpers.db_connection()
                            with con:
                                cur = con.cursor()
                                cur.execute(
                                    "SELECT * FROM indicators where type='IPv4' OR type='IPv6' OR type='Domain' OR type='Network'")
                                network = cur.fetchall()

            if newdict['inputtype'] == "IPv4" or newdict['inputtype'] == "Domain" or newdict[
                    'inputtype'] == "Network" or newdict['inputtype'] == "IPv6":
                con = libs.helpers.db_connection()
                with con:
                    cur = con.cursor()
                    cur.execute(
                        "SELECT * FROM indicators where type='IPv4' OR type='IPv6' OR type='Domain' OR type='Network'")
                    network = cur.fetchall()
                return render_template('networks.html', network=network)

            elif newdict['diamondmodel'] == "Victim":
                con = libs.helpers.db_connection()
                with con:
                    cur = con.cursor()
                    cur.execute(
                        "SELECT * FROM indicators where diamondmodel='Victim'")
                    victims = cur.fetchall()
                return render_template('victims.html', network=victims)
            elif newdict['inputtype'] == "Hash":
                con = libs.helpers.db_connection()
                with con:
                    cur = con.cursor()
                    cur.execute(
                        "SELECT * FROM indicators where type='Hash'")
                    files = cur.fetchall()
                return render_template('files.html', network=files)
            else:
                con = libs.helpers.db_connection()
                with con:
                    cur = con.cursor()
                    cur.execute(
                        "SELECT * FROM indicators where type='Threat Actor'")
                    threatactors = cur.fetchall()
                return render_template('threatactors.html', network=threatactors)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/edit/<uid>', methods=['POST', 'GET'])
@login_required
def editobject(uid):
    try:
        con = libs.helpers.db_connection()
        newdict = {}
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from indicators where id='" + uid + "'")
            http = cur.fetchall()
            http = http[0]
            names = [description[0] for description in cur.description]
            for i in names:
                if i is None:
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
        con = libs.helpers.db_connection()
        with con:
            cur = con.cursor()
            cur.execute("DELETE FROM indicators WHERE id=?", (uid,))
            cur = con.cursor()
            cur.execute(
                "SELECT * FROM indicators where type='IPv4' OR type='IPv6' OR type='Domain' OR type='Network'")
            network = cur.fetchall()
        return render_template('networks.html', network=network)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/delete/threatactor/<uid>', methods=['GET'])
@login_required
def deletethreatactorobject(uid):
    try:
        con = libs.helpers.db_connection()
        with con:
            cur = con.cursor()
            cur.execute("DELETE FROM indicators WHERE id=?", (uid,))
            cur = con.cursor()
            cur.execute("SELECT * FROM indicators where type='Threat Actor'")
            threatactors = cur.fetchall()
        return render_template('threatactors.html', network=threatactors)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/delete/victims/<uid>', methods=['GET'])
@login_required
def deletevictimobject(uid):
    try:
        con = libs.helpers.db_connection()
        with con:
            cur = con.cursor()
            cur.execute("DELETE FROM indicators WHERE id=?", (uid,))
            cur = con.cursor()
            cur.execute("SELECT * FROM indicators where diamondmodel='victim'")
            cur.fetchall()
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/delete/files/<uid>', methods=['GET'])
@login_required
def deletefilesobject(uid):
    try:
        con = libs.helpers.db_connection()
        with con:
            cur = con.cursor()
            cur.execute("DELETE FROM indicators WHERE id=?", (uid,))
            cur = con.cursor()
            cur.execute("SELECT * FROM indicators where type='Hash'")
            cur.fetchall()
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
        # Make sure we're updating the settings instead of overwriting them
        con = libs.helpers.db_connection()
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from settings")
            cur.fetchall()
            if 'threatcrowd' in newdict.keys():
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET threatcrowd = 'on'")
            else:
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET threatcrowd = 'off'")
            if 'ptinfo' in newdict.keys():
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET ptinfo = 'on'")
            else:
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET ptinfo = 'off'")
            if 'vtinfo' in newdict.keys():
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET vtinfo = 'on'")
            else:
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET vtinfo = 'off'")
            if 'vtfile' in newdict.keys():
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET vtfile = 'on'")
            else:
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET vtfile = 'off'")
            if 'circlinfo' in newdict.keys():
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET circlinfo = 'on'")
            else:
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET circlinfo = 'off'")
            if 'circlssl' in newdict.keys():
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET circlssl = 'on'")
            else:
                with con:
                    cur = con.cursor()
                    cur.execute("UPDATE settings SET circlssl = 'off'")
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
                cur.execute(
                    "UPDATE settings SET apikey = '" + newdict['apikey'] + "'")
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
                cur.execute(
                    "UPDATE settings SET odnskey = '" + newdict['odnskey'] + "'")
            with con:
                cur = con.cursor()
                cur.execute(
                    "UPDATE settings SET httpproxy = '" + newdict['httpproxy'] + "'")
            with con:
                cur = con.cursor()
                cur.execute(
                    "UPDATE settings SET httpsproxy = '" + newdict['httpsproxy'] + "'")
            with con:
                cur = con.cursor()
                cur.execute(
                    "UPDATE settings SET cuckoohost = '" + newdict['cuckoohost'] + "'")
            with con:
                cur = con.cursor()
                cur.execute(
                    "UPDATE settings SET cuckooapiport = '" + newdict['cuckooapiport'] + "'")

            with con:
                cur = con.cursor()
                cur.execute(
                    "UPDATE settings SET circlusername = '" + newdict['circlusername'] + "'")
            with con:
                cur = con.cursor()
                cur.execute(
                    "UPDATE settings SET circlpassword = '" + newdict['circlpassword'] + "'")
            with con:
                cur = con.cursor()
                cur.execute(
                    "UPDATE settings SET ptkey = '" + newdict['ptkey'] + "'")  
        con = libs.helpers.db_connection()
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from settings")
            newrecords = cur.fetchall()
            newrecords = newrecords[0]
        return render_template('settings.html', records=newrecords)
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
        taglist = newdict['tags'].split(",")
        con = libs.helpers.db_connection()
        with con:
            for t in newdict:
                if t == "id":
                    pass
                else:
                    try:
                        cur = con.cursor()
                        cur.execute("UPDATE indicators SET " + t + "= '" + newdict[
                                    t] + "' WHERE id = '" + newdict['id'] + "'")
                    except:
                        cur = con.cursor()
                        cur.execute(
                            "ALTER TABLE indicators ADD COLUMN " + t + " TEXT DEFAULT ''")
                        cur.execute("UPDATE indicators SET " + t + "= '" + newdict[
                                    t] + "' WHERE id = '" + newdict['id'] + "'")
        with con:
            cur = con.cursor()
            cur.execute(
                "SELECT * from indicators where id='" + newdict['id'] + "'")
            http = cur.fetchall()
            http = http[0]
            names = [description[0] for description in cur.description]
            for i in names:
                tempdict[i] = http[i]
            cur.execute("SELECT * from settings")
            settingsvars = cur.fetchall()
            settingsvars = settingsvars[0]
            cur.execute("SELECT relationships from indicators where id='" + newdict['id'] + "'")
            rels = cur.fetchall()
            rels = rels[0][0]
        rellist = rels.split(",")
        temprel = {}
        for rel in rellist:
            try:
                with con:
                    cur = con.cursor()
                    cur.execute("SELECT * from indicators where object='" + str(rel) + "'")
                    reltype = cur.fetchall()
                    reltype = reltype[0]
                    temprel[reltype['object']] = reltype['type'] 
            except:
                pass
        reldata = len(temprel)
        # Returns object information with updated values
        jsonvt = ""
        whoisdata = ""
        odnsdata = ""
        circldata = ""
        circlssl = ""
        ptdata = ""
        # Run ipwhois or domainwhois based on the type of indicator
        if str(http['type']) == "IPv4" or str(http['type']) == "IPv6":
            if settingsvars['vtinfo'] == "on":
                jsonvt = libs.virustotal.vt_ipv4_lookup(str(http['object']))
            if settingsvars['whoisinfo'] == "on":
                whoisdata = libs.whoisinfo.ipwhois(str(http['object']))
            if settingsvars['odnsinfo'] == "on":
                odnsdata = libs.investigate.ip_query(str(http['object']))
            if settingsvars['circlinfo'] == "on":
                circldata = libs.circl.circlquery(str(http['object']))
            if settingsvars['circlssl'] == "on":
                circlssl = libs.circl.circlssl(str(http['object']))
            if settingsvars['ptinfo'] == "on":
                ptdata = libs.passivetotal.pt(str(http['object']))
        elif str(http['type']) == "Domain":
            if settingsvars['whoisinfo'] == "on":
                whoisdata = libs.whoisinfo.domainwhois(str(http['object']))
            if settingsvars['vtinfo'] == "on":
                jsonvt = libs.virustotal.vt_domain_lookup(str(http['object']))
            if settingsvars['odnsinfo'] == "on":
                odnsdata = libs.investigate.domain_categories(
                    str(http['object']))
            if settingsvars['circlinfo'] == "on":
                circldata = libs.circl.circlquery(str(http['object']))
            if settingsvars['ptinfo'] == "on":
                ptdata = libs.passivetotal.pt(str(http['object']))
        if newdict['type'] == "Threat Actor":
            return render_template(
                'threatactorobject.html', records=tempdict, jsonvt=jsonvt, whoisdata=whoisdata,
                settingsvars=settingsvars,temprel=temprel, reldata=reldata, taglist=taglist)
        elif newdict['diamondmodel'] == "Victim":
            return render_template(
                'victimobject.html', records=tempdict, jsonvt=jsonvt, whoisdata=whoisdata,
                settingsvars=settingsvars,temprel=temprel, reldata=reldata,taglist=taglist, ptdata=ptdata )
        elif newdict['type'] == "Hash":
            return render_template(
                'fileobject.html', records=tempdict, settingsvars=settingsvars,temprel=temprel, reldata=reldata, taglist=taglist)
        else:
            return render_template(
                'networkobject.html', records=tempdict, jsonvt=jsonvt, whoisdata=whoisdata, odnsdata=odnsdata,
                settingsvars=settingsvars,temprel=temprel, reldata=reldata,taglist=taglist, circldata=circldata, circlssl=circlssl, ptdata=ptdata)
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
        con = libs.helpers.db_connection()
        newdict = {}
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from indicators where id='" + uid + "'")
            http = cur.fetchall()
            http = http[0]
            names = [description[0] for description in cur.description]
            for i in names:
                if i is None:
                    newdict[i] == ""
                else:
                    newdict[i] = str(http[i])
            cur.execute("SELECT * from settings")
            settingsvars = cur.fetchall()
            settingsvars = settingsvars[0]
            cur.execute("SELECT relationships from indicators where id='" + uid + "'")
            rels = cur.fetchall()
            rels = rels[0][0]
        rellist = rels.split(",")
        taglist = newdict['tags'].split(",")
        temprel = {}
        for rel in rellist:
            try:
                with con:
                    cur = con.cursor()
                    cur.execute("SELECT * from indicators where object='" + str(rel) + "'")
                    reltype = cur.fetchall()
                    reltype = reltype[0]
                    temprel[reltype['object']] = reltype['type'] 
            except:
                pass
        reldata = len(temprel)
        jsonvt = ""
        whoisdata = ""
        odnsdata = ""
        circldata = ""
        circlssl = ""
        ptdata = ""
        # Run ipwhois or domainwhois based on the type of indicator
        if str(http['type']) == "IPv4" or str(http['type']) == "IPv6":
            if settingsvars['vtinfo'] == "on":
                jsonvt = libs.virustotal.vt_ipv4_lookup(str(http['object']))
            if settingsvars['whoisinfo'] == "on":
                whoisdata = libs.whoisinfo.ipwhois(str(http['object']))
            if settingsvars['odnsinfo'] == "on":
                odnsdata = libs.investigate.ip_query(str(http['object']))
            if settingsvars['circlinfo'] == "on":
                circldata = libs.circl.circlquery(str(http['object']))
            if settingsvars['circlssl'] == "on":
                circlssl = libs.circl.circlssl(str(http['object']))
            if settingsvars['ptinfo'] == "on":
                ptdata = libs.passivetotal.pt(str(http['object']))
        elif str(http['type']) == "Domain":
            if settingsvars['whoisinfo'] == "on":
                whoisdata = libs.whoisinfo.domainwhois(str(http['object']))
            if settingsvars['vtinfo'] == "on":
                jsonvt = libs.virustotal.vt_domain_lookup(str(http['object']))
            if settingsvars['odnsinfo'] == "on":
                odnsdata = libs.investigate.domain_categories(str(http['object']))
            if settingsvars['circlinfo'] == "on":
                circldata = libs.circl.circlquery(str(http['object']))
            if settingsvars['ptinfo'] == "on":
                ptdata = libs.passivetotal.pt(str(http['object']))
        if settingsvars['whoisinfo'] == "on":
            if str(http['type']) == "Domain":
                address = str(whoisdata['city']) + ", " + str(whoisdata['country'])
            else:
                address = str(whoisdata['nets'][0]['city']) + ", " + str(
                    whoisdata['nets'][0]['country'])
        else:
            address = "Information about " + str(http['object'])
        return render_template(
            'networkobject.html', records=newdict, jsonvt=jsonvt, whoisdata=whoisdata,
            odnsdata=odnsdata, settingsvars=settingsvars, address=address, ptdata=ptdata, temprel=temprel, circldata=circldata, circlssl=circlssl, reldata=reldata, taglist=taglist)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/threatactors/<uid>/info', methods=['GET'])
@login_required
def threatactorobject(uid):
    try:
        con = libs.helpers.db_connection()
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from indicators where id='" + uid + "'")
            http = cur.fetchall()
            http = http[0]
            cur.execute("SELECT relationships from indicators where id='" + uid + "'")
            rels = cur.fetchall()
            rels = rels[0][0]
        rellist = rels.split(",")
        temprel = {}
        for rel in rellist:
            try:
                with con:
                    cur = con.cursor()
                    cur.execute("SELECT * from indicators where object='" + str(rel) + "'")
                    reltype = cur.fetchall()
                    reltype = reltype[0]
                    temprel[reltype['object']] = reltype['type'] 
            except:
                pass
        reldata = len(temprel)
        return render_template('threatactorobject.html', records=http, temprel=temprel, reldata=reldata)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/relationships/<uid>', methods=['GET'])
@login_required
def relationships(uid):
    try:
        con = libs.helpers.db_connection()
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from indicators where id='" + uid + "'")
            http = cur.fetchall()
            http = http[0]
            cur = con.cursor()
            cur.execute("SELECT * from indicators")
            indicators = cur.fetchall()
            cur.execute("SELECT relationships from indicators where id='" + uid + "'")
            rels = cur.fetchall()
            rels = rels[0][0]
        rellist = rels.split(",")
        temprel = {}
        for rel in rellist:
            try:
                with con:
                    cur = con.cursor()
                    cur.execute("SELECT * from indicators where object='" + str(rel) + "'")
                    reltype = cur.fetchall()
                    reltype = reltype[0]
                    temprel[reltype['object']] = reltype['type'] 
            except:
                pass
        reldata = len(temprel)
        return render_template('addrelationship.html', records=http, indicators=indicators)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/addrelationship', methods=['GET','POST'])
@login_required
def addrelationship():
    try:
        something = request.form
        imd = ImmutableMultiDict(something)
        records = libs.helpers.convert(imd)
        newdict = {}
        for i in records:
            newdict[i] = records[i]
        con = libs.helpers.db_connection()
        with con:
            cur = con.cursor()
            cur.execute("UPDATE indicators SET relationships=relationships || '" + newdict['indicator'] + ",' WHERE id='" + newdict['id'] + "'")
        if newdict['type'] == "IPv4" or newdict['type'] == "IPv6" or newdict['type'] == "Domain" or newdict['type'] == "Network":
            return redirect(url_for('objectsummary', uid=str(newdict['id'])))
        elif newdict['type'] ==  "Hash":
            return redirect(url_for('filesobject', uid=str(newdict['id'])))
        elif newdict['type'] == "Entity":
            return redirect(url_for('victimobject', uid=str(newdict['id'])))
        elif newdict['type'] == "Threat Actor":
            return redirect(url_for('threatactorobject', uid=str(newdict['id'])))  
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    try:
        con = libs.helpers.db_connection()
        with con:
            tempdict = {}
            cur = con.cursor()
            cur.execute("SELECT key from users where user='" + str(
                current_user.user).lower() + "'")
            http = cur.fetchall()
            http = http[0]
            names = [description[0] for description in cur.description]
            for i in names:
                if i is None:
                    tempdict[i] == ""
                else:
                    tempdict[i] = http[i]
        something = request.form
        imd = ImmutableMultiDict(something)
        records = libs.helpers.convert(imd)
        newdict = {}
        for i in records:
            newdict[i] = records[i]
        if 'currentpw' in newdict:
            if hashlib.md5(newdict['currentpw'].encode('utf-8')).hexdigest() == tempdict['key']:
                if newdict['newpw'] == newdict['newpwvalidation']:
                    with con:
                        try:
                            cur = con.cursor()
                            cur.execute("UPDATE users SET key='" + hashlib.md5(newdict['newpw'].encode(
                                'utf-8')).hexdigest() + "' WHERE user='" + str(current_user.user).lower() + "'")
                            errormessage = "Password updated successfully."
                            return render_template('profile.html', errormessage=errormessage)
                        except lite.Error as er:
                            print 'er:', er.__dict__
                else:
                    errormessage = "New passwords don't match."
                    return render_template('profile.html', errormessage=errormessage)
            else:
                errormessage = "Current password is incorrect."
                return render_template('profile.html', errormessage=errormessage)
        return render_template('profile.html')
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/victims/<uid>/info', methods=['GET'])
@login_required
def victimobject(uid):
    try:
        con = libs.helpers.db_connection()
        newdict = {}
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from indicators where id='" + uid + "'")
            http = cur.fetchall()
            http = http[0]
            names = [description[0] for description in cur.description]
            for i in names:
                if i is None:
                    newdict[i] == ""
                else:
                    newdict[i] = str(http[i])
            cur.execute("SELECT * from settings")
            settingsvars = cur.fetchall()
            settingsvars = settingsvars[0]
            cur.execute("SELECT relationships from indicators where id='" + uid + "'")
            rels = cur.fetchall()
            rels = rels[0][0]
        taglist = newdict['tags'].split(",")
        rellist = rels.split(",")
        temprel = {}
        for rel in rellist:
            try:
                with con:
                    cur = con.cursor()
                    cur.execute("SELECT * from indicators where object='" + str(rel) + "'")
                    reltype = cur.fetchall()
                    reltype = reltype[0]
                    temprel[reltype['object']] = reltype['type'] 
            except:
                pass
        reldata = len(temprel)
        jsonvt = ""
        whoisdata = ""
        odnsdata = ""
        circldata = ""
        circlssl = ""
        ptdata = ""
        # Run ipwhois or domainwhois based on the type of indicator
        if str(http['type']) == "IPv4" or str(http['type']) == "IPv6":
            if settingsvars['vtinfo'] == "on":
                jsonvt = libs.virustotal.vt_ipv4_lookup(str(http['object']))
            if settingsvars['whoisinfo'] == "on":
                whoisdata = libs.whoisinfo.ipwhois(str(http['object']))
            if settingsvars['odnsinfo'] == "on":
                odnsdata = libs.investigate.ip_query(str(http['object']))
            if settingsvars['circlinfo'] == "on":
                circldata = libs.circl.circlquery(str(http['object']))
            if settingsvars['circlssl'] == "on":
                circlssl = libs.circl.circlssl(str(http['object']))
            if settingsvars['ptinfo'] == "on":
                ptdata = libs.passivetotal.pt(str(http['object']))
        elif str(http['type']) == "Domain":
            if settingsvars['whoisinfo'] == "on":
                whoisdata = libs.whoisinfo.domainwhois(str(http['object']))
            if settingsvars['vtinfo'] == "on":
                jsonvt = libs.virustotal.vt_domain_lookup(str(http['object']))
            if settingsvars['odnsinfo'] == "on":
                odnsdata = libs.investigate.domain_categories(
                    str(http['object']))
            if settingsvars['circlinfo'] == "on":
                circldata = libs.circl.circlquery(str(http['object']))
            if settingsvars['ptinfo'] == "on":
                ptdata = libs.passivetotal.pt(str(http['object']))
        if settingsvars['whoisinfo'] == "on":
            if str(http['type']) == "Domain":
                address = str(whoisdata['city']) + ", " + str(
                    whoisdata['country'])
            else:
                address = str(whoisdata['nets'][0]['city']) + ", " + str(
                    whoisdata['nets'][0]['country'])
        else:
            address = "Information about " + str(http['object'])
        return render_template(
            'victimobject.html', records=newdict, jsonvt=jsonvt, whoisdata=whoisdata,
            odnsdata=odnsdata, circldata=circldata, circlssl=circlssl, settingsvars=settingsvars, address=address,temprel=temprel, reldata=reldata, taglist=taglist, ptdata=ptdata)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/files/<uid>/info', methods=['GET'])
@login_required
def filesobject(uid):
    try:
        con = libs.helpers.db_connection()
        newdict = {}
        with con:
            cur = con.cursor()
            cur.execute("SELECT * from indicators where id='" + uid + "'")
            http = cur.fetchall()
            http = http[0]
            names = [description[0] for description in cur.description]
            for i in names:
                if i is None:
                    newdict[i] == ""
                else:
                    newdict[i] = str(http[i])
            cur.execute("SELECT * from settings")
            settingsvars = cur.fetchall()
            settingsvars = settingsvars[0]
            address = "Information about " + str(http['object'])
            cur.execute("SELECT relationships from indicators where id='" + uid + "'")
            rels = cur.fetchall()
            rels = rels[0][0]
        rellist = rels.split(",")
        taglist = newdict['tags'].split(",")
        temprel = {}
        for rel in rellist:
            try:
                with con:
                    cur = con.cursor()
                    cur.execute("SELECT * from indicators where object='" + str(rel) + "'")
                    reltype = cur.fetchall()
                    reltype = reltype[0]
                    temprel[reltype['object']] = reltype['type'] 
            except:
                pass
        reldata = len(temprel)
        if settingsvars['vtfile'] == "on":
            jsonvt = libs.virustotal.vt_hash_lookup(str(http['object']))
        else:
            jsonvt=""
        return render_template('fileobject.html', records=newdict, settingsvars=settingsvars, address=address,temprel=temprel, reldata=reldata, jsonvt=jsonvt, taglist=taglist)
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/import', methods=['GET', 'POST'])
@login_required
def import_indicators():
    cuckoo_tasks = libs.cuckoo.get_tasks()
    return render_template('import.html', cuckoo_tasks=cuckoo_tasks)

@app.route('/download/<uid>', methods=['GET'])
@login_required
def download(uid):
    if uid == 'unknown':
        uid = ""
    file = io.BytesIO()
    # fieldnames =
    # ['id','object','type','firstseen','lastseen','diamondmodel','campaign','confidence','comments']
    con = libs.helpers.db_connection()
    indlist = []
    with con:
        cur = con.cursor()
        cur.execute(
            "SELECT * FROM indicators WHERE campaign = '" + str(uid) + "'")
        http = cur.fetchall()
        cur.execute("SELECT * from indicators")
        fieldnames = [description[0] for description in cur.description]

    for i in http:
        indicators = []
        for item in i:
            if item is None or item == "":
                indicators.append("-")
            else:
                indicators.append(str(item))
        indlist.append(indicators)

    w = csv.writer(file)
    try:
        w.writerow(fieldnames)
        w.writerows(indlist)
        response = make_response(file.getvalue())
        response.headers[
            "Content-Disposition"] = "attachment; filename=" + uid + "-campaign.csv"
        response.headers["Content-type"] = "text/csv"
        return response
    except Exception as e:
        print str(e)
        pass

@app.route('/api/v1/indicators', methods=['GET'])
def get_indicators():
    con = libs.helpers.db_connection()
    indicatorlist = []
    with con:
        cur = con.cursor()
        cur.execute("SELECT * FROM indicators")
        indicators = cur.fetchall()
        names = [description[0] for description in cur.description]
        for ind in indicators:
            newdict = {}
            for i in names:
                newdict[i] = str(ind[i])
            indicatorlist.append(newdict)
    return jsonify({'indicators': indicatorlist})

@app.route('/api/v1/ip_indicator/<ip>', methods=['GET'])
def get_ip_indicator(ip):
    con = libs.helpers.db_connection()
    indicatorlist = []
    with con:
        cur = con.cursor()
        cur.execute("SELECT * FROM indicators where object='" + ip + "'")
        indicators = cur.fetchall()
        names = [description[0] for description in cur.description]
        for ind in indicators:
            newdict = {}
            for i in names:
                newdict[i] = str(ind[i])
            indicatorlist.append(newdict)
    return jsonify({'indicator': indicatorlist})

@app.route('/api/v1/network', methods=['GET'])
def get_network():
    con = libs.helpers.db_connection()
    indicatorlist = []
    with con:
        cur = con.cursor()
        cur.execute("SELECT * FROM indicators where type='IPv4' or type='IPv6' or type='Domain' or type='Network'")
        indicators = cur.fetchall()
        names = [description[0] for description in cur.description]
        for ind in indicators:
            newdict = {}
            for i in names:
                newdict[i] = str(ind[i])
            indicatorlist.append(newdict)
    return jsonify({'network_indicators': indicatorlist})

@app.route('/api/v1/threatactors', methods=['GET'])
def get_threatactors():
    con = libs.helpers.db_connection()
    indicatorlist = []
    with con:
        cur = con.cursor()
        cur.execute("SELECT * FROM indicators where type='Threat Actor'")
        indicators = cur.fetchall()
        names = [description[0] for description in cur.description]
        for ind in indicators:
            newdict = {}
            for i in names:
                newdict[i] = str(ind[i])
            indicatorlist.append(newdict)
    return jsonify({'threatactors': indicatorlist})

@app.route('/api/v1/files', methods=['GET'])
def get_files():
    con = libs.helpers.db_connection()
    indicatorlist = []
    with con:
        cur = con.cursor()
        cur.execute("SELECT * FROM indicators where type='Hash'")
        indicators = cur.fetchall()
        names = [description[0] for description in cur.description]
        for ind in indicators:
            newdict = {}
            for i in names:
                newdict[i] = str(ind[i])
            indicatorlist.append(newdict)
    return jsonify({'files': indicatorlist})

@app.route('/api/v1/campaigns/<campaign>', methods=['GET'])
def get_campaigns(campaign):
    con = libs.helpers.db_connection()
    indicatorlist = []
    campaign = urllib.unquote(campaign).decode('utf8')
    with con:
        cur = con.cursor()
        cur.execute("SELECT * FROM indicators where campaign='" + campaign + "'")
        indicators = cur.fetchall()
        names = [description[0] for description in cur.description]
        for ind in indicators:
            newdict = {}
            for i in names:
                newdict[i] = str(ind[i])
            indicatorlist.append(newdict)
    return jsonify({'campaigns': indicatorlist})

@app.route('/api/v1/relationships/<ip>', methods=['GET'])
def get_relationships(ip):
    con = libs.helpers.db_connection()
    indicatorlist = []
    with con:
        cur = con.cursor()
        cur.execute("SELECT relationships from indicators where object='" + ip + "'")
        rels = cur.fetchall()
        rels = rels[0][0]
        rellist = rels.split(",")
        temprel = {}
        for rel in rellist:
            try:
                with con:
                    cur = con.cursor()
                    cur.execute("SELECT * from indicators where object='" + str(rel) + "'")
                    reltype = cur.fetchall()
                    reltype = reltype[0]
                    temprel[reltype['object']] = reltype['type'] 
            except:
                pass
    return jsonify({'relationships': temprel})


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', help="Specify port to listen on")
    parser.add_argument('-d', '--debug', help="Run in debug mode", action="store_true")
    parser.add_argument('-db', '--database', help="Path to sqlite database")
    args = parser.parse_args()


    #if args.database:
    #    db_file = args.database
    #else:
    libs.helpers.setup_db()

    if not args.port:
        port = 8888
    else:
        port = args.port

    if not args.debug:
        debug = False
    else:
        debug = True


    app.run(host='0.0.0.0', port=port, debug=debug)