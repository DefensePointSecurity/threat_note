#!/usr/bin/env python

#
# threat_note v3.0                                      #
# Developed By: Brian Warehime                          #
# Defense Point Security (defpoint.com)                 #
# October 26, 2015                                      #
#

import argparse
import csv
import hashlib
import io
import re
import time

import libs.circl
import libs.cuckoo
import libs.farsight
import libs.helpers
import libs.investigate
import libs.passivetotal
import libs.shodan
import libs.virustotal
import libs.whoisinfo
from flask import Flask
from flask import flash
from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask.ext.login import LoginManager
from flask.ext.login import current_user
from flask.ext.login import login_required
from flask.ext.login import login_user
from flask.ext.login import logout_user
from flask.ext.wtf import Form
from libs.API import tn_api
from libs.database import db_session
from libs.database import init_db
from libs.models import Indicator
from libs.models import Setting
from libs.models import User
from werkzeug.datastructures import ImmutableMultiDict
from wtforms import PasswordField
from wtforms import StringField
from wtforms.validators import DataRequired

#
# Configuration #
#

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yek_terces'
lm = LoginManager()
lm.init_app(app)
lm.login_view = 'login'

app.register_blueprint(tn_api)


class LoginForm(Form):
    user = StringField('user', validators=[DataRequired()])
    key = PasswordField('key', validators=[DataRequired()])

    def get_user(self):
        return db_session.query(User).filter_by(user=self.user.data.lower(), key=hashlib.md5(
            self.key.data.encode('utf-8')).hexdigest()).first()


class RegisterForm(Form):
    user = StringField('user', validators=[DataRequired()])
    key = PasswordField('key', validators=[DataRequired()])
    email = StringField('email')


#
# Creating routes #
#

@lm.user_loader
def load_user(id):
    return db_session.query(User).filter_by(_id=id).first()


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = db_session.query(User).filter_by(user=form.user.data.lower()).first()
        if user:
            flash('User exists.')
        else:
            user = User(form.user.data.lower(), form.key.data, form.email.data)
            db_session.add(user)

            # Set up the settings table when the first user is registered.
            if not Setting.query.filter_by(_id=1).first():
                settings = Setting('off', 'off', 'off', 'off', 'off', 'off', 'off', 'off', 'off', '', '', '',
                                   '', '', '', '', '', '', '', '')
                db_session.add(settings)
            # Commit all database changes once they have been completed
            db_session.commit()
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


@app.route('/', methods=['GET'])
@login_required
def home():
    try:
        counts = Indicator.query.distinct(Indicator._id).count()
        types = Indicator.query.group_by(Indicator.type).all()
        network = Indicator.query.order_by(Indicator._id).limit(5).all()
        campaigns = Indicator.query.group_by(Indicator.campaign).all()
        taglist = Indicator.query.distinct(Indicator.tags).all()

        # Generate Tag Cloud
        tags = []
        for object in taglist:
            if object.tags == "":
                pass
            else:
                for tag in object.tags.split(","):
                    tags.append(tag.strip())

        dictcount = {}
        dictlist = []
        typecount = {}
        typelist = []

        # Generate Campaign Statistics Graph
        for object in campaigns:
            c = Indicator.query.filter_by(campaign=object.campaign).count()
            if object.campaign == '':
                dictcount["category"] = "Unknown"
                tempx = (float(c) / float(counts)) * 100
                dictcount["value"] = round(tempx, 2)
            else:
                dictcount["category"] = object.campaign
                tempx = (float(c) / float(counts)) * 100
                dictcount["value"] = round(tempx, 2)

            dictlist.append(dictcount.copy())

        # Generate Indicator Type Graph
        for t in types:
            c = Indicator.query.filter_by(type=t.type).count()
            typecount["category"] = t.type
            tempx = float(c) / float(counts)
            newtemp = tempx * 100
            typecount["value"] = round(newtemp, 2)
            typelist.append(typecount.copy())
        favs = []

        # Add Import from Cuckoo button to Dashboard page
        settings = Setting.query.filter_by(_id=1).first()
        if 'on' in settings.cuckoo:
            importsetting = True
        else:
            importsetting = False

        return render_template('dashboard.html', networks=dictlist, network=network, favs=favs, typelist=typelist,
                               taglist=tags, importsetting=importsetting)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/about', methods=['GET'])
@login_required
def about():
    return render_template('about.html')


@app.route('/tags', methods=['GET'])
@login_required
def tags():
    try:
        # Grab tags
        taglist = dict()
        rows = Indicator.query.distinct(Indicator.tags).all()
        for row in rows:
            if row.tags:
                for tag in row.tags.split(','):
                    taglist[tag] = list()
        # Match indicators to tags
        del rows, row
        for tag, indicators in taglist.iteritems():
            rows = Indicator.query.filter(Indicator.tags.like('%' + tag + '%')).all()
            tmp = {}
            for row in rows:
                tmp[row.object] = row.type
                indicators.append(tmp)

        return render_template('tags.html', tags=taglist)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/networks', methods=['GET'])
@login_required
def networks():
    try:
        # Grab only network indicators
        network = Indicator.query.filter(Indicator.type.in_(('IPv4', 'IPv6', 'Domain', 'Network'))).all()
        return render_template('networks.html', network=network)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/threatactors', methods=['GET'])
@login_required
def threatactors():
    try:
        # Grab threat actors
        threatactors = Indicator.query.filter(Indicator.type == ('Threat Actor')).all()
        return render_template('threatactors.html', network=threatactors)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/victims', methods=['GET'])
@login_required
def victims():
    try:
        # Grab victims
        victims = Indicator.query.filter(Indicator.diamondmodel == ('Victim')).all()
        return render_template('victims.html', network=victims)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/files', methods=['GET'])
@login_required
def files():
    try:
        # Grab files/hashes
        files = Indicator.query.filter(Indicator.type == ('Hash')).all()
        return render_template('files.html', network=files)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/campaigns', methods=['GET'])
@login_required
def campaigns():
    try:
        # Grab campaigns
        campaignents = dict()
        rows = Indicator.query.group_by(Indicator.campaign).all()
        for c in rows:
            if c.campaign == '':
                name = 'Unknown'
            else:
                name = c.campaign
            campaignents[name] = list()
        # Match indicators to campaigns
        for camp, indicators in campaignents.iteritems():
            if camp == 'Unknown':
                camp = ''
            rows = Indicator.query.filter(Indicator.campaign == camp).all()
            tmp = {}
            for i in rows:
                tmp[i.object] = i.type
                indicators.append(tmp)
        return render_template('campaigns.html', campaignents=campaignents)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/settings', methods=['GET'])
@login_required
def settings():
    try:
        settings = Setting.query.filter_by(_id=1).first()
        return render_template('settings.html', records=settings)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/campaign/<uid>/info', methods=['GET'])
@login_required
def campaignsummary(uid):
    try:
        http = Indicator.query.filter_by(object=uid).first()
        # Run ipwhois or domainwhois based on the type of indicator
        if str(http.type) == "IPv4" or str(http.type) == "IPv6" or str(http.type) == "Domain" or \
                str(http.type) == "Network":
            return redirect(url_for('objectsummary', uid=http.object))
        elif str(http.type) == "Hash":
            return redirect(url_for('filesobject', uid=http.object))
        else:
            return redirect(url_for('threatactorobject', uid=http.object))
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

        # Import indicators from Cuckoo for the selected analysis task
        if 'type' in records and 'cuckoo' in records['type']:
            host_data, dns_data, sha1, firstseen = libs.cuckoo.report_data(records['cuckoo_task_id'])
            if host_data and dns_data and sha1 and firstseen:
                # Import IP Indicators from Cuckoo Task
                for ip in host_data:
                    object = Indicator.query.filter_by(object=ip).first()
                    if object is None:
                        indicator = Indicator(ip.strip(), 'IPv4', firstseen, '', 'Infrastructure', records['campaign'],
                                              'Low', '', records['tags'], '')
                        db_session.add(indicator)
                        db_session.commit()
                    else:
                        errormessage = "Entry already exists in database."
                        return render_template('newobject.html', errormessage=errormessage,
                                               inputtype=records['inputtype'], inputobject=ip,
                                               inputfirstseen=records['inputfirstseen'],
                                               inputlastseen=records['inputlastseen'],
                                               inputcampaign=records['inputcampaign'],
                                               comments=records['comments'],
                                               diamondmodel=records['diamondmodel'],
                                               tags=records['tags'])
                    # Import Domain Indicators from Cuckoo Task
                    for dns in dns_data:
                        object = Indicator.query.filter_by(object=dns['requst']).first()
                        if object is None:
                            indicator = Indicator(dns['request'], 'Domain', firstseen, '', 'Infrastructure',
                                                  records['campaign'], 'Low', '', records['tags'], '')
                            db_session.add(indicator)
                            db_session.commit()
                        else:
                            errormessage = "Entry already exists in database."
                            return render_template('newobject.html', errormessage=errormessage,
                                                   inputtype=records['inputtype'], inputobject=ip,
                                                   inputfirstseen=records['inputfirstseen'],
                                                   inputlastseen=records['inputlastseen'],
                                                   inputcampaign=records['inputcampaign'],
                                                   comments=records['comments'],
                                                   diamondmodel=records['diamondmodel'],
                                                   tags=records['tags'])
                    # Import File/Hash Indicators from Cuckoo Task
                    object = Indicator.query.filter_by(object=sha1).first()
                    if object is None:
                        indicator = Indicator(sha1, 'Hash', firstseen, '', 'Capability',
                                              records['campaign'], 'Low', '', records['tags'], '')
                        db_session.add(indicator)
                        db_session.commit()
                    else:
                        errormessage = "Entry already exists in database."
                        return render_template('newobject.html', errormessage=errormessage,
                                               inputtype=records['inputtype'], inputobject=ip,
                                               inputfirstseen=records['inputfirstseen'],
                                               inputlastseen=records['inputlastseen'],
                                               inputcampaign=records['inputcampaign'],
                                               comments=records['comments'],
                                               diamondmodel=records['diamondmodel'],
                                               tags=records['tags'])

                # Redirect to Dashboard after successful import
                return redirect(url_for('home'))
            else:
                errormessage = 'Task is not a file analysis'
                return redirect(url_for('import_indicators'))

        if 'inputtype' in records:
            # Makes sure if you submit an IPv4 indicator, it's an actual IP
            # address.
            ipregex = re.match(
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', records['inputobject'])
            # Convert the inputobject of IP or Domain to a list for Bulk Add functionality.
            records['inputobject'] = records['inputobject'].split(',')
            for newobject in records['inputobject']:
                if records['inputtype'] == "IPv4":
                    if ipregex:
                        object = Indicator.query.filter_by(object=newobject).first()
                        if object is None:
                            ipv4_indicator = Indicator(newobject.strip(), records['inputtype'],
                                                       records['inputfirstseen'], records['inputlastseen'],
                                                       records['diamondmodel'], records['inputcampaign'],
                                                       records['confidence'], records['comments'], records['tags'], None)
                            db_session.add(ipv4_indicator)
                            db_session.commit()
                            network = Indicator.query.filter(Indicator.type.in_(
                                ('IPv4', 'IPv6', 'Domain', 'Network'))).all()
                        else:
                            errormessage = "Entry already exists in database."
                            return render_template('newobject.html', errormessage=errormessage,
                                                   inputtype=records['inputtype'], inputobject=newobject,
                                                   inputfirstseen=records['inputfirstseen'],
                                                   inputlastseen=records['inputlastseen'],
                                                   inputcampaign=records['inputcampaign'],
                                                   comments=records['comments'],
                                                   diamondmodel=records['diamondmodel'],
                                                   tags=records['tags'])

                    else:
                        errormessage = "Not a valid IP Address."
                        newobject = ', '.join(records['inputobject'])
                        return render_template('newobject.html', errormessage=errormessage,
                                               inputtype=records['inputtype'],
                                               inputobject=records, inputfirstseen=records['inputfirstseen'],
                                               inputlastseen=records['inputlastseen'],
                                               confidence=records['confidence'], inputcampaign=records['inputcampaign'],
                                               comments=records['comments'], diamondmodel=records['diamondmodel'],
                                               tags=records['tags'])
                else:
                    object = Indicator.query.filter_by(object=newobject).first()
                    if object is None:
                        indicator = Indicator(newobject.strip(), records['inputtype'], records['inputfirstseen'],
                                              records['inputlastseen'], records['diamondmodel'], records['inputcampaign'],
                                              records['confidence'], records['comments'], records['tags'], None)
                        db_session.add(indicator)
                        db_session.commit()
                    else:
                        errormessage = "Entry already exists in database."
                        return render_template('newobject.html', errormessage=errormessage,
                                               inputtype=records['inputtype'], inputobject=newobject,
                                               inputfirstseen=records['inputfirstseen'],
                                               inputlastseen=records['inputlastseen'],
                                               inputcampaign=records['inputcampaign'],
                                               comments=records['comments'],
                                               diamondmodel=records['diamondmodel'],
                                               tags=records['tags'])

            # TODO: Change 'network' to 'object' in HTML templates to standardize on verbiage
            if records['inputtype'] == "IPv4" or records['inputtype'] == "Domain" or records['inputtype'] == "Network"\
                    or records['inputtype'] == "IPv6":
                network = Indicator.query.filter(Indicator.type.in_(('IPv4', 'IPv6', 'Domain', 'Network'))).all()
                return render_template('networks.html', network=network)

            elif records['diamondmodel'] == "Victim":
                victims = Indicator.query.filter(Indicator.diamondmodel == ('Victim')).all()
                return render_template('victims.html', network=victims)

            elif records['inputtype'] == "Hash":
                files = Indicator.query.filter(Indicator.type == ('Hash')).all()
                return render_template('files.html', network=files)

            else:
                threatactors = Indicator.query.filter(Indicator.type == ('Threat Actors')).all()
                return render_template('threatactors.html', network=threatactors)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/edit/<uid>', methods=['POST', 'GET'])
@login_required
def editobject(uid):
    try:
        http = Indicator.query.filter_by(object=uid).first()
        newdict = libs.helpers.row_to_dict(http)
        return render_template('neweditobject.html', entry=newdict)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/delete/network/<uid>', methods=['GET'])
@login_required
def deletenetworkobject(uid):
    try:
        Indicator.query.filter_by(object=uid).delete()
        db_session.commit()
        network = Indicator.query.filter(Indicator.type.in_(('IPv4', 'IPv6', 'Domain', 'Network'))).all()
        return render_template('networks.html', network=network)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/delete/threatactor/<uid>', methods=['GET'])
@login_required
def deletethreatactorobject(uid):
    try:
        Indicator.query.filter_by(object=uid).delete()
        db_session.commit()
        threatactors = Indicator.query.filter_by(type='Threat Actor')
        return render_template('threatactors.html', network=threatactors)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/delete/victims/<uid>', methods=['GET'])
@login_required
def deletevictimobject(uid):
    try:
        Indicator.query.filter_by(object=uid).delete()
        db_session.commit()
        victims = Indicator.query.filter_by(diamondmodel='Victim')
        return render_template('victims.html', network=victims)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/delete/files/<uid>', methods=['GET'])
@login_required
def deletefilesobject(uid):
    try:
        Indicator.query.filter_by(object=uid).delete()
        db_session.commit()
        files = Indicator.query.filter_by(type='Hash')
        return render_template('victims.html', network=files)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/update/settings/', methods=['POST'])
@login_required
def updatesettings():
    try:
        something = request.form
        imd = ImmutableMultiDict(something)
        newdict = libs.helpers.convert(imd)

        # Query the first set of settings, could query custom settings for individual users
        settings = Setting.query.filter_by(_id=1).first()

        # Make sure we're updating the settings instead of overwriting them
        if 'threatcrowd' in newdict.keys():
            settings.threatcrowd = 'on'
        else:
            settings.threatcrowd = 'off'
        if 'ptinfo' in newdict.keys() and newdict['ptkey'] is not '':
            settings.ptinfo = 'on'
        else:
            settings.ptinfo = 'off'
        if 'cuckoo' in newdict.keys():
            settings.cuckoo = 'on'
        else:
            settings.cuckoo = 'off'
        if 'vtinfo' in newdict.keys() and newdict['apikey'] is not '':
            settings.vtinfo = 'on'
        else:
            settings.vtinfo = 'off'
        if 'vtfile' in newdict.keys() and newdict['apikey'] is not '':
            settings.vtfile = 'on'
        else:
            settings.vtfile = 'off'
        if 'circlinfo' in newdict.keys() and newdict['circlusername'] is not '':
            settings.circlinfo = 'on'
        else:
            settings.circlinfo = 'off'
        if 'circlssl' in newdict.keys() and newdict['circlusername'] is not '':
            settings.circlssl = 'on'
        else:
            settings.circlssl = 'off'
        if 'whoisinfo' in newdict.keys():
            settings.whoisinfo = 'on'
        else:
            settings.whoisinfo = 'off'
        if 'farsightinfo' in newdict.keys() and newdict['farsightkey'] is not '':
            settings.farsightinfo = 'on'
        else:
            settings.farsightinfo = 'off'
        if 'odnsinfo' in newdict.keys() and newdict['odnskey'] is not '':
            settings.odnsinfo = 'on'
        else:
            settings.odnsinfo = 'off'

        settings.farsightkey = newdict['farsightkey']
        settings.apikey = newdict['apikey']
        settings.odnskey = newdict['odnskey']
        settings.httpproxy = newdict['httpproxy']
        settings.httpsproxy = newdict['httpsproxy']
        settings.cuckoohost = newdict['cuckoohost']
        settings.cuckooapiport = newdict['cuckooapiport']
        settings.circlusername = newdict['circlusername']
        settings.circlpassword = newdict['circlpassword']
        settings.ptkey = newdict['ptkey']

        db_session.commit()
        settings = Setting.query.first()

        return render_template('settings.html', records=settings)
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
        # taglist = records['tags'].split(",") - Unused
        # indicator = Indicator.query.filter_by(object=records['object']).first() - Unused

        try:
            Indicator.query.filter_by(object=records['object']).update(records)
        except Exception as e:
            # SQLAlchemy does not outright support altering tables.
            for k, v in records.iteritems():
                if Indicator.query.group_by(k).first() is None:
                    print 'ALTER Table'
                    # db_session.engine.execute("ALTER TABLE indicators ADD COLUMN " + k + " TEXT DEFAULT ''")

        db_session.commit()

        # db_session.execute('ALTER  TABLE indicators ADD COLUMN')

        # con = libs.helpers.db_connection()
        # with con:
        #    cur = con.cursor()
        #    cur.execute(
        #        "ALTER TABLE indicators ADD COLUMN " + t + " TEXT DEFAULT ''")
        #    cur.execute("UPDATE indicators SET " + t + "= '" + records[
        #                t] + "' WHERE id = '" + records['id'] + "'")

        if records['type'] == "IPv4" or records['type'] == "IPv6" or records['type'] == "Domain" or \
                records['type'] == "Network":
            return redirect(url_for('objectsummary', uid=str(records['object'])))
        elif records['type'] == "Hash":
            return redirect(url_for('filesobject', uid=str(records['object'])))
        elif records['type'] == "Entity":
            return redirect(url_for('victimobject', uid=str(records['object'])))
        elif records['type'] == "Threat Actor":
            return redirect(url_for('threatactorobject', uid=str(records['object'])))
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
        row = Indicator.query.filter_by(object=uid).first()
        newdict = libs.helpers.row_to_dict(row)
        settings = Setting.query.filter_by(_id=1).first()
        taglist = row.tags.split(",")

        temprel = {}
        if row.relationships:
            rellist = row.relationships.split(",")
            for rel in rellist:
                row = Indicator.query.filter_by(object=rel).first()
                temprel[row.object] = row.type

        reldata = len(temprel)
        jsonvt = ""
        whoisdata = ""
        odnsdata = ""
        circldata = ""
        circlssl = ""
        ptdata = ""
        farsightdata = ""
        # shodandata = ""
        # Run ipwhois or domainwhois based on the type of indicator
        if str(row.type) == "IPv4" or str(row.type) == "IPv6":
            if settings.vtinfo == "on":
                jsonvt = libs.virustotal.vt_ipv4_lookup(str(row.object))
            if settings.whoisinfo == "on":
                whoisdata = libs.whoisinfo.ipwhois(str(row.object))
            if settings.odnsinfo == "on":
                odnsdata = libs.investigate.ip_query(str(row.object))
            if settings.circlinfo == "on":
                circldata = libs.circl.circlquery(str(row.object))
            if settings.circlssl == "on":
                circlssl = libs.circl.circlssl(str(row.object))
            if settings.ptinfo == "on":
                ptdata = libs.passivetotal.pt(str(row.object))
            if settings.farsightinfo == "on":
                farsightdata = libs.farsight.farsightip(str(row.object))
        elif str(row.type) == "Domain":
            if settings.whoisinfo == "on":
                whoisdata = libs.whoisinfo.domainwhois(str(row.object))
            if settings.vtinfo == "on":
                jsonvt = libs.virustotal.vt_domain_lookup(str(row.object))
            if settings.odnsinfo == "on":
                odnsdata = libs.investigate.domain_categories(str(row.object))
            if settings.circlinfo == "on":
                circldata = libs.circl.circlquery(str(row.object))
            if settings.ptinfo == "on":
                ptdata = libs.passivetotal.pt(str(row.object))
            if settings.farsightinfo == "on":
                farsightdata = libs.farsight.farsightdomain(str(row.object))
        if settings.whoisinfo == "on":
            if str(row.type) == "Domain":
                address = str(whoisdata['city']) + ", " + str(whoisdata['country'])
            else:
                address = str(whoisdata['nets'][0]['city']) + ", " + str(
                    whoisdata['nets'][0]['country'])
        else:
            address = "Information about " + str(row.object)
        return render_template('networkobject.html', records=newdict, jsonvt=jsonvt, whoisdata=whoisdata,
                               odnsdata=odnsdata, settingsvars=settings, address=address,
                               ptdata=ptdata, temprel=temprel, circldata=circldata, circlssl=circlssl, reldata=reldata,
                               taglist=taglist, farsightdata=farsightdata)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/threatactors/<uid>/info', methods=['GET'])
@login_required
def threatactorobject(uid):
    try:
        row = Indicator.query.filter(Indicator.object == uid).first()
        newdict = libs.helpers.row_to_dict(row)

        temprel = {}
        if row.relationships:
            rellist = row.relationships.split(",")
            for rel in rellist:
                reltype = Indicator.query.filter(Indicator.object == rel)
                temprel[reltype.object] = reltype.type

        reldata = len(temprel)
        return render_template('threatactorobject.html', records=newdict, temprel=temprel, reldata=reldata)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/relationships/<uid>', methods=['GET'])
@login_required
def relationships(uid):
    try:
        row = Indicator.query.filter_by(object=uid).first()
        indicators = Indicator.query.all()
        if row.relationships:
            rellist = row.relationships.split(",")
            temprel = {}
            for rel in rellist:
                reltype = Indicator.query.filter_by(object=rel).first()
                temprel[reltype.object] = reltype.type
        return render_template('addrelationship.html', records=row, indicators=indicators)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/addrelationship', methods=['GET', 'POST'])
@login_required
def addrelationship():
    try:
        something = request.form
        imd = ImmutableMultiDict(something)
        records = libs.helpers.convert(imd)

        row = Indicator.query.filter_by(object=records['id']).first()
        row.relationships = records['indicator']
        db_session.commit()

        if records['type'] == "IPv4" or records['type'] == "IPv6" or records['type'] == "Domain" or \
                records['type'] == "Network":
            return redirect(url_for('objectsummary', uid=str(records['id'])))
        elif records['type'] == "Hash":
            return redirect(url_for('filesobject', uid=str(records['id'])))
        elif records['type'] == "Entity":
            return redirect(url_for('victimobject', uid=str(records['id'])))
        elif records['type'] == "Threat Actor":
            return redirect(url_for('threatactorobject', uid=str(records['id'])))
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    try:
        user = User.query.filter_by(user=current_user.user.lower()).first()
        something = request.form
        imd = ImmutableMultiDict(something)
        records = libs.helpers.convert(imd)

        if 'currentpw' in records:
            if hashlib.md5(records['currentpw'].encode('utf-8')).hexdigest() == user.key:
                if records['newpw'] == records['newpwvalidation']:
                    user.key = hashlib.md5(records['newpw'].encode('utf-8')).hexdigest()
                    db_session.commit()
                    errormessage = "Password updated successfully."
                    return render_template('profile.html', errormessage=errormessage)
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
        http = Indicator.query.filter(Indicator.object == uid).first()
        newdict = libs.helpers.row_to_dict(http)
        settings = Setting.query.filter_by(_id=1).first()
        taglist = http.tags.split(",")

        temprel = {}
        if http.relationships:
            rellist = http.relationships.split(",")
            for rel in rellist:
                reltype = Indicator.query.filter(Indicator.object == rel)
                temprel[reltype.object] = reltype.type

        reldata = len(temprel)
        jsonvt = ""
        whoisdata = ""
        odnsdata = ""
        circldata = ""
        circlssl = ""
        ptdata = ""
        farsightdata = ""
        # shodaninfo = ""
        # Run ipwhois or domainwhois based on the type of indicator
        if str(http.type) == "IPv4" or str(http.type) == "IPv6":
            if settings.vtinfo == "on":
                jsonvt = libs.virustotal.vt_ipv4_lookup(str(http.object))
            if settings.whoisinfo == "on":
                whoisdata = libs.whoisinfo.ipwhois(str(http.object))
            if settings.odnsinfo == "on":
                odnsdata = libs.investigate.ip_query(str(http.object))
            if settings.circlinfo == "on":
                circldata = libs.circl.circlquery(str(http.object))
            if settings.circlssl == "on":
                circlssl = libs.circl.circlssl(str(http.object))
            if settings.ptinfo == "on":
                ptdata = libs.passivetotal.pt(str(http.object))
            if settings.farsightinfo == "on":
                farsightdata = libs.farsight.farsightip(str(http.object))
        elif str(http.type) == "Domain":
            if settings.whoisinfo == "on":
                whoisdata = libs.whoisinfo.domainwhois(str(http.object))
            if settings.vtinfo == "on":
                jsonvt = libs.virustotal.vt_domain_lookup(str(http.object))
            if settings.odnsinfo == "on":
                odnsdata = libs.investigate.domain_categories(
                    str(http.object))
            if settings.circlinfo == "on":
                circldata = libs.circl.circlquery(str(http.object))
            if settings.ptinfo == "on":
                ptdata = libs.passivetotal.pt(str(http.object))
        if settings.whoisinfo == "on":
            if str(http.type) == "Domain":
                address = str(whoisdata['city']) + ", " + str(
                    whoisdata['country'])
            else:
                address = str(whoisdata['nets'][0]['city']) + ", " + str(
                    whoisdata['nets'][0]['country'])
        else:
            address = "Information about " + str(http.object)
        return render_template('victimobject.html', records=newdict, jsonvt=jsonvt, whoisdata=whoisdata,
                               odnsdata=odnsdata, circldata=circldata, circlssl=circlssl, settingsvars=settings,
                               address=address, temprel=temprel, reldata=reldata, taglist=taglist, ptdata=ptdata,
                               farsightdata=farsightdata)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/files/<uid>/info', methods=['GET'])
@login_required
def filesobject(uid):
    try:
        http = Indicator.query.filter(Indicator.object == uid).first()
        newdict = libs.helpers.row_to_dict(http)
        settings = Setting.query.filter_by(_id=1).first()
        taglist = http.tags.split(",")

        temprel = {}
        if http.relationships:
            rellist = http.relationships.split(",")
            for rel in rellist:
                reltype = Indicator.query.filter(Indicator.object == rel)
                temprel[reltype.object] = reltype.type

        reldata = len(temprel)
        if settings.vtfile == "on":
            jsonvt = libs.virustotal.vt_hash_lookup(str(http.object))
        else:
            jsonvt = ""
        return render_template('fileobject.html', records=newdict, settingsvars=settings, address=http.object,
                               temprel=temprel, reldata=reldata, jsonvt=jsonvt, taglist=taglist)
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
    rows = Indicator.query.filter_by(campaign=uid).all()
    for row in rows:
        print row

    con = libs.helpers.db_connection()
    with con:
        cur = con.cursor()
        cur.execute(
            "SELECT * FROM indicators WHERE campaign = '" + str(uid) + "'")
        http = cur.fetchall()
        cur.execute("SELECT * from indicators")
        fieldnames = [description[0] for description in cur.description]

    indlist = []
    for i in http:
        indicators = []
        for item in i:
            if item is None or item == "":
                indicators.append("-")
            else:
                indicators.append(str(item))
        indlist.append(indicators)
    try:
        out_file = io.BytesIO()
        w = csv.writer(out_file)
        w.writerow(fieldnames)
        w.writerows(indlist)
        response = make_response(out_file.getvalue())
        response.headers[
            "Content-Disposition"] = "attachment; filename=" + uid + "-campaign.csv"
        response.headers["Content-type"] = "text/csv"
        return response
    except Exception as e:
        print str(e)
        pass


@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--host', default="127.0.0.1", help="Specify the host IP address")
    parser.add_argument('-p', '--port', default=8888, help="Specify port to listen on")
    parser.add_argument('-d', '--debug', default=False, help="Run in debug mode", action="store_true")
    parser.add_argument('-db', '--database', help="Path to sqlite database - Not Implemented")
    args = parser.parse_args()

    if args.database:
        # TODO
        libs.database.db_file = args.database

    init_db()
    app.run(host=args.host, port=args.port, debug=args.debug)
