
from instantauth.sessionhandler import SessionHandler

class InMemorySession(object):
    mapper={}

    def __init__(self, id):
        self.id = id
        self.public_key = str(id)
        self.private_key = 'p' + str(id)
        self.mapper[self.public_key] = self


class TestSessionHandler(SessionHandler):
    def session_from_session_key(self, session_key, type=None):
        return InMemorySession(session_key)

    def session_from_public_key(self, public_key):
        try:
            return InMemorySession.mapper[public_key]
        except:
            return InMemorySession(public_key)

    def get_public_key(self, session):
        return session.public_key

    def get_private_key(self, session):
        return session.private_key