import urllib

import helpers
from database import db_session
# V2 Flask-Restful Version
from flask import Blueprint
from flask import jsonify
from flask import request
from flask_restful import Api
from flask_restful import Resource
from models import Indicator

tn_api = Blueprint('tn_api', __name__)

# V1 API


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
    # indicatorlist = [] # Unused
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


# TODO: Add Auth - http://blog.miguelgrinberg.com/post/restful-authentication-with-flask
# TODO: Add Error for No Results

api = Api(tn_api)

# Base Data Model: Indicator


class Indicators(Resource):

    def get(self):
        indicators = Indicator.query.all()
        indicatorlist = []
        for ind in indicators:
            indicatorlist.append(helpers.row_to_dict(ind))
        return jsonify({'indicators': indicatorlist})

    def post(self):
        data = request.get_json()

        if Indicator.query.filter(Indicator.object == data['object']).first():
            return {'error': 'indicator {} already exists'.format(data['object'])}, 409
        elif not helpers.valid_type(data['type']):
            return {'error': 'indicator {} is not of valid type'.format(data['object'])}, 400
        elif not helpers.valid_diamond_model(data['diamondmodel']):
            return {'error': 'indicator {} has invalid dimond model {}'.format(data['object'], data['diamondmodel'])}, 400
        else:
            indicator = Indicator(
                data['object'],
                data['type'],
                data['firstseen'],
                data['lastseen'],
                data['diamondmodel'],
                data['campaign'],
                data['confidence'],
                data['comments'],
                data['tags'],
                None)
            db_session.add(indicator)
            db_session.commit()

            indicators = Indicator.query.filter(Indicator.object == data['object']).first()
            return {'indicator': helpers.row_to_dict(indicators)}, 201

api.add_resource(Indicators, '/api/v2/indicators')


class Indicator_Singular(Resource):

    def get(self, ind):
        ind = urllib.unquote(ind).decode('utf8')
        indicator = Indicator.query.filter(Indicator.object == ind).first()
        if indicator:
            return {ind: helpers.row_to_dict(indicator)}
        else:
            return {ind: 'indicator not found'}, 404

api.add_resource(Indicator_Singular, '/api/v2/indicator/<string:ind>')

# Specific Data Models: Network Indicators, Threat Actors, Victims, & Files


class NetworkIndicators(Resource):

    def get(self):
        indicators = Indicator.query.filter(Indicator.type.in_(('IPv4', 'IPv6', 'Domain', 'Network'))).all()
        indicatorlist = []
        for ind in indicators:
            indicatorlist.append(helpers.row_to_dict(ind))
        return jsonify({'network_indicators': indicatorlist})

api.add_resource(NetworkIndicators, '/api/v2/networks')


class ThreatActors(Resource):

    def get(self):
        indicators = Indicator.query.filter(Indicator.type == 'Threat Actor').all()
        indicatorlist = []
        for ind in indicators:
            indicatorlist.append(helpers.row_to_dict(ind))
        return jsonify({'threatactors': indicatorlist})

api.add_resource(ThreatActors, '/api/v2/threat_actors')


class Victims(Resource):

    def get(self):
        indicators = Indicator.query.filter(Indicator.type == 'Victim').all()
        indicatorlist = []
        for ind in indicators:
            indicatorlist.append(helpers.row_to_dict(ind))
        return jsonify({'victims': indicatorlist})

api.add_resource(Victims, '/api/v2/victims')


class Files(Resource):

    def get(self):
        indicators = Indicator.query.filter(Indicator.type == 'Hash')
        indicatorlist = []
        for ind in indicators:
            indicatorlist.append(helpers.row_to_dict(ind))
        return {'files': indicatorlist}

api.add_resource(Files, '/api/v2/files')


# Secondary Data Types: Campaigns, Relationships, & Tags

class Campaigns(Resource):

    def get(self):
        indicators = Indicator.query.all()
        campaignlist = []
        for ind in indicators:
            if ind.campaign not in campaignlist:
                campaignlist.append(ind.campaign)
        return {'campaigns': campaignlist}

api.add_resource(Campaigns, '/api/v2/campaigns')


class Campaign(Resource):

    def get(self, campaign):
        campaign = urllib.unquote(campaign).decode('utf8')
        indicators = Indicator.query.filter(Indicator.campaign == campaign).all()
        indicatorlist = []
        for ind in indicators:
            indicatorlist.append(helpers.row_to_dict(ind))
        return jsonify({'campaigns': indicatorlist})

api.add_resource(Campaign, '/api/v2/campaign/<string:campaign>')


# TODO - Relationships aren't working, so this is untestable
class Relationships(Resource):

    def get(self, arg):
        return {'status': 'not implimented'}

    def post(self, arg):
        return {'status': 'not implimented'}

# api.add_resource(Relationships, '/api/v2/relationships')

# TODO - Relationships aren't working, so this is untestable


class Relationship(Resource):

    def get(self):
        return {'status': 'not implimented'}

# api.add_resource(Relationship, '/api/v2/relationship/<int:id>')


class Tags(Resource):

    def get(self):
        indicators = Indicator.query.all()
        taglist = []
        for ind in indicators:
            for tag in ind.tags.split(', '):
                if tag not in taglist:
                    taglist.append(tag)
        return {'tags': taglist}

api.add_resource(Tags, '/api/v2/tags')


class Tag(Resource):

    def get(self, tag):
        indicators = Indicator.query.all()
        indicatorlist = []
        for ind in indicators:
            print ind
            for tag in ind.tags.split(', '):
                if tag is tag:
                    indicatorlist.append(helpers.row_to_dict(ind))
        return {'tag': tag, 'indicators': indicatorlist}

api.add_resource(Tag, '/api/v2/tag/<string:tag>')
