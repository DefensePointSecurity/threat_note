from flask import Blueprint
from flask import jsonify
import helpers
import urllib

tn_api = Blueprint('tn_api', __name__)

@tn_api.route('/api/v1/indicators', methods=['GET'])
def get_indicators():
    con = helpers.db_connection()
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


@tn_api.route('/api/v1/ip_indicator/<ip>', methods=['GET'])
def get_ip_indicator(ip):
    con = helpers.db_connection()
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


@tn_api.route('/api/v1/network', methods=['GET'])
def get_network():
    con = helpers.db_connection()
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


@tn_api.route('/api/v1/threatactors', methods=['GET'])
def get_threatactors():
    con = helpers.db_connection()
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


@tn_api.route('/api/v1/files', methods=['GET'])
def get_files():
    con = helpers.db_connection()
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


@tn_api.route('/api/v1/campaigns/<campaign>', methods=['GET'])
def get_campaigns(campaign):
    con = helpers.db_connection()
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


@tn_api.route('/api/v1/relationships/<ip>', methods=['GET'])
def get_relationships(ip):
    con = helpers.db_connection()
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
