import urllib

import helpers
from database import db_session
# V2 Flask-Restful Version
from flask import Blueprint
from flask import abort
from flask import request
from flask_restful import Api
from flask_restful import Resource
from models import Indicator
from models import User

tn_api = Blueprint('tn_api', __name__)
api = Api(tn_api)


def apikey(f):
    def d(*args, **kwargs):

        apikeys = [user.apikey for user in User.query.all()]

        if request.args.get('key') and request.args.get('key') in apikeys:
            return f(*args, **kwargs)
        else:
            abort(401)
    return d


class Indicators(Resource):

    @apikey
    def get(self):
        indicators = Indicator.query.all()
        if indicators:
            return {'indicators': [helpers.row_to_dict(ind) for ind in indicators]}
        else:
            return {}, 204

    @apikey
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

api.add_resource(Indicators, '/api/indicators')


class Indicator_Singular(Resource):

    @apikey
    def get(self, ind):
        ind = urllib.unquote(ind).decode('utf8')
        indicator = Indicator.query.filter(Indicator.object == ind).first()
        if indicator:
            return {ind: helpers.row_to_dict(indicator)}
        else:
            return {ind: 'indicator not found'}, 404

api.add_resource(Indicator_Singular, '/api/indicator/<string:ind>')

# Specific Data Models: Network Indicators, Threat Actors, Victims, & Files


class NetworkIndicators(Resource):

    @apikey
    def get(self):
        indicators = Indicator.query.filter(Indicator.type.in_(('IPv4', 'IPv6', 'Domain', 'Network'))).all()

        if indicators:
            return {'network_indicators': helpers.row_to_dict(ind) for ind in indicators}
        else:
            return {}, 204

api.add_resource(NetworkIndicators, '/api/networks')


class ThreatActors(Resource):

    @apikey
    def get(self):
        indicators = Indicator.query.filter(Indicator.type == 'Threat Actor').all()

        if indicators:
            return {'threatactors': helpers.row_to_dict(ind) for ind in indicators}
        else:
            return {}, 204

api.add_resource(ThreatActors, '/api/threat_actors')


class Victims(Resource):

    @apikey
    def get(self):
        indicators = Indicator.query.filter(Indicator.type == 'Victim').all()

        if indicators:
            return {'victims': helpers.row_to_dict(ind) for ind in indicators}
        else:
            return {}, 204

api.add_resource(Victims, '/api/victims')


class Files(Resource):

    @apikey
    def get(self):
        indicators = Indicator.query.filter(Indicator.type == 'Hash')
        indicatorlist = []
        for ind in indicators:
            indicatorlist.append(helpers.row_to_dict(ind))
        return {'files': indicatorlist}

api.add_resource(Files, '/api/files')


# Secondary Data Types: Campaigns, Relationships, & Tags

class Campaigns(Resource):

    @apikey
    def get(self):
        indicators = Indicator.query.all()
        campaignlist = []
        for ind in indicators:
            if ind.campaign not in campaignlist:
                campaignlist.append(ind.campaign)
        return {'campaigns': campaignlist}

api.add_resource(Campaigns, '/api/campaigns')


class Campaign(Resource):

    @apikey
    def get(self, campaign):
        campaign = urllib.unquote(campaign).decode('utf8')
        indicators = Indicator.query.filter(Indicator.campaign == campaign).all()

        if indicators:
            return {'campaigns': helpers.row_to_dict(ind) for ind in indicators}
        else:
            return {}, 204

api.add_resource(Campaign, '/api/campaign/<string:campaign>')


# TODO - Relationships aren't working, so this is untestable
class Relationships(Resource):

    def get(self, arg):
        return {'status': 'not implimented'}

    def post(self, arg):
        return {'status': 'not implimented'}

# api.add_resource(Relationships, '/api/relationships')

# TODO - Relationships aren't working, so this is untestable


class Relationship(Resource):

    @apikey
    def get(self, target):

        indicator = Indicator.query.filter(Indicator.object == target)[0]

        if indicator:
            try:
                indicatorlist = []
                for indicator in indicator.relationships.split(","):
                    inc = helpers.row_to_dict(Indicator.query.filter(Indicator.object == indicator)[0])
                    if inc not in indicatorlist:
                        indicatorlist.append(inc)

                return {target: indicatorlist}
            except AttributeError:
                return {target: []}, 404
        else:
            return {target: 'Indicator not found.'}, 404

api.add_resource(Relationship, '/api/relationship/<string:target>')


class Tags(Resource):

    @apikey
    def get(self):
        indicators = Indicator.query.all()
        taglist = []
        for ind in indicators:
            for tag in ind.tags.split(', '):
                if tag not in taglist:
                    taglist.append(tag)
        return {'tags': taglist}

api.add_resource(Tags, '/api/tags')


class Tag(Resource):

    @apikey
    def get(self, tag):
        indicators = Indicator.query.all()
        indicatorlist = []
        for ind in indicators:
            print ind
            for tag in ind.tags.split(', '):
                if tag is tag:
                    indicatorlist.append(helpers.row_to_dict(ind))
        return {'tag': tag, 'indicators': indicatorlist}

api.add_resource(Tag, '/api/tag/<string:tag>')
