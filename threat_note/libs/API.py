from flask import Blueprint
from flask import jsonify
import helpers
import urllib
from models import Indicator

tn_api = Blueprint('tn_api', __name__)

@tn_api.route('/api/v1/indicators', methods=['GET'])
def get_indicators():
    indicators = Indicator.query.all()
    indicatorlist = []
    for ind in indicators:
        indicatorlist.append(helpers.row_to_dict(ind))
    return jsonify({'indicators': indicatorlist})


@tn_api.route('/api/v1/ip_indicator/<ip>', methods=['GET'])
def get_ip_indicator(ip):
    indicators = Indicator.query.filter(Indicator.object == ip).first()
    indicatorlist = []
    indicatorlist.append(helpers.row_to_dict(indicators))
    return jsonify({'indicator': indicatorlist})


@tn_api.route('/api/v1/network', methods=['GET'])
def get_network():
    indicators = Indicator.query.filter(Indicator.type.in_(('IPv4', 'IPv6', 'Domain', 'Network'))).all()
    indicatorlist = []
    for ind in indicators:
        indicatorlist.append(helpers.row_to_dict(ind))
    return jsonify({'network_indicators': indicatorlist})


@tn_api.route('/api/v1/threatactors', methods=['GET'])
def get_threatactors():
    indicators = Indicator.query.filter(Indicator.type == 'Threat Actor').first()
    indicatorlist = []
    indicatorlist.append(helpers.row_to_dict(indicators))
    return jsonify({'threatactors': indicatorlist})


@tn_api.route('/api/v1/files', methods=['GET'])
def get_files():
    indicators = Indicator.query.filter(Indicator.type == 'Hash').first()
    indicatorlist = []
    indicatorlist.append(helpers.row_to_dict(indicators))
    return jsonify({'files': indicatorlist})


@tn_api.route('/api/v1/campaigns/<campaign>', methods=['GET'])
def get_campaigns(campaign):
    campaign = urllib.unquote(campaign).decode('utf8')
    indicators = Indicator.query.filter(Indicator.campaign == campaign).all()
    indicatorlist = []
    for ind in indicators:
        indicatorlist.append(helpers.row_to_dict(ind))
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
