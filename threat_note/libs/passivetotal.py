import json

import helpers
import requests
from models import Setting


def pt(indicator):
    try:
        settings = Setting.query.filter_by(_id=1).first()
        apikey = settings.ptkey
        url = 'https://www.passivetotal.org/api/v1/passive'
        params = {'api_key': apikey, 'query': indicator}
        response = requests.get(url, params=params)
        json_response = json.loads(response.content)
        return json_response
    except:
        pass
