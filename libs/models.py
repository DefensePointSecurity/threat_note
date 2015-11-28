from sqlalchemy import Column, Integer, String
from database import Base
import hashlib

class User(Base):
    __tablename__ = 'users'
    _id = Column('_id', Integer, primary_key=True, autoincrement=True)
    user = Column('user', String)
    email = Column('email', String)
    password = Column('password', String)

    def __init__(self, user, password, email):
        self.user = user.lower()
        self.password = hashlib.md5(password.encode('utf-8')).hexdigest()
        self.email = email

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self._id

    def __repr__(self):
        return '<User %r>' % (self.name)


class Setting(Base):
    __tablename__ = 'settings'
    _id = Column('_id', Integer, primary_key=True, autoincrement=True)
    apikey = Column('apikey', String)
    odnskey = Column('odnskey', String)
    vtinfo = Column('vtinfo', String)
    whoisinfo = Column('whoisinfo', String)
    odnsinfo = Column('odnsinfo', String)
    httpproxy = Column('httpproxy', String)
    httpsproxy = Column('httpsproxy', String)
    threatcrowd = Column('threatcrowd', String)
    vtfile = Column('vtfile', String)
    circlinfo = Column('circlinfo', String)
    circlusername = Column('circlusername', String)
    circlpassword = Column('circlpassword', String)
    circlssl = Column('circlssl', String)
    ptinfo = Column('ptinfo', String)
    ptkey = Column('ptkey', String)
    cuckoo = Column('cuckoo', String)
    cuckoohost = Column('cuckoohost', String)
    cuckooapiport = Column('cuckooapiport', String)
    farsightinfo = Column('farsightinfo', String)
    farsightkey = Column('farsightkey', String)

    def __init__(self, user, key, email):
       pass


class Indicator(Base):
    __tablename__ = 'indicators'
    _id = Column('_id', Integer, primary_key=True, autoincrement=True)
    object = Column('object', String)
    type = Column('type', String)
    firstseen = Column('firstseen', String)
    lastseen = Column('lastseen', String)
    diamondmodel = Column('diamondmodel', String)
    campaign = Column('campaign', String)
    confidence = Column('confidence', String)
    comments = Column('comments', String)
    tags = Column('tags', String)
    relationships = Column('relationships', String)

    def __init__(self, object, type, firstseen, lastseen, diamondmodel, campaign, confidence, comments, tags,
                 relationships):
        self.object = object
        self.type = type
        self.firstseen = firstseen
        self.lastseen = lastseen
        self.diamondmodel = diamondmodel
        self.campaign = campaign
        self.confidence = confidence
        self.comments = comments
        self.tags = tags
        self.relationships = relationships