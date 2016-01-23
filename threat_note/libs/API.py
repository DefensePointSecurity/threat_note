import urllib

import helpers
# V2 Flask-Restful Version
from flask import Blueprint
from flask import jsonify
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


class Indicators(Resource):

    def get(self):
        indicators = Indicator.query.all()
        indicatorlist = []
        for ind in indicators:
            indicatorlist.append(helpers.row_to_dict(ind))
        return jsonify({'indicators': indicatorlist})

    # TODO: def post(self, arg):
        # pass

api.add_resource(Indicators, '/api/v2/indicators')


class NetworkIndicators(Resource):

    def get(self):
        indicators = Indicator.query.filter(Indicator.type.in_(('IPv4', 'IPv6', 'Domain', 'Network'))).all()
        indicatorlist = []
        for ind in indicators:
            indicatorlist.append(helpers.row_to_dict(ind))
        return jsonify({'network_indicators': indicatorlist})

    # def post(self, arg):
    #     pass

api.add_resource(NetworkIndicators, '/api/v2/networks')


class NetworkIndicator(Resource):

    def get(self, network_indicator):
        indicators = Indicator.query.filter(Indicator.object == network_indicator).first()
        indicatorlist = []
        indicatorlist.append(helpers.row_to_dict(indicators))
        return jsonify({'indicator': indicatorlist})

    def post(self, arg):
        pass

api.add_resource(NetworkIndicator, '/api/v2/network/<string:network_indicator>')


class ThreatActors(Resource):

    def get(self):
        indicators = Indicator.query.filter(Indicator.type == 'Threat Actor').all()
        indicatorlist = []
        for ind in indicators:
            indicatorlist.append(helpers.row_to_dict(ind))
        return jsonify({'threatactors': indicatorlist})

    # def post(self, arg):
    #     pass

api.add_resource(ThreatActors, '/api/v2/threat_actors')


class ThreatActor(Resource):

    def get(self, actor):
        actor = urllib.unquote(actor).decode('utf8')
        indicators = Indicator.query.filter(Indicator.object == actor).first()
        indicatorlist = []
        indicatorlist.append(helpers.row_to_dict(indicators))
        return jsonify({'indicator': indicatorlist})

    def post(self, arg):
        pass

api.add_resource(ThreatActor, '/api/v2/threat_actor/<string:actor>')


class Files(Resource):

    def get(self):
        indicators = Indicator.query.filter(Indicator.type == 'Hash')
        indicatorlist = []
        for ind in indicators:
            indicatorlist.append(helpers.row_to_dict(ind))
        return jsonify({'files': indicatorlist})

    def post(self, arg):
        pass

api.add_resource(Files, '/api/v2/files')


class File(Resource):

    def get(self, hash):
        indicators = Indicator.query.filter(Indicator.object == hash).first()
        indicatorlist = []
        indicatorlist.append(helpers.row_to_dict(indicators))
        return jsonify({'indicator': indicatorlist})

    def post(self, arg):
        pass

api.add_resource(File, '/api/v2/file/<string:hash>')


class Campaigns(Resource):

    def get(self):
        indicators = Indicator.query.all()
        campaignlist = []
        for ind in indicators:
            if ind.campaign not in campaignlist:
                campaignlist.append(ind.campaign)
        return jsonify({'campaigns': campaignlist})

api.add_resource(Campaigns, '/api/v2/campaigns')


class Campaign(Resource):

    def get(self, campaign):
        campaign = urllib.unquote(campaign).decode('utf8')
        indicators = Indicator.query.filter(Indicator.campaign == campaign).all()
        indicatorlist = []
        for ind in indicators:
            indicatorlist.append(helpers.row_to_dict(ind))
        return jsonify({'campaigns': indicatorlist})

    def post(self, arg):
        pass

api.add_resource(Campaign, '/api/v2/campaign/<string:campaign>')


class Relationships(Resource):

    def get(self, arg):
        pass

    def post(self, arg):
        pass

api.add_resource(Relationships, '/api/v2/relationships')


class Relationship(Resource):

    def get(self, arg):
        pass

    def post(self, arg):
        pass

api.add_resource(Relationship, '/api/v2/relationship/<int:id>')


class Tags(Resource):

    def get(self, arg):
        pass

    def post(self, arg):
        pass

api.add_resource(Tags, '/api/v2/tags')


class Tag(Resource):

    def get(self, arg):
        pass

    def post(self, arg):
        pass

api.add_resource(Tag, '/api/v2/tag/<int:id>')
