"""
Stand-in for samba.auth.

SamDBHelper.__init__ passes system_session() as the LDB session_info.
The stub returns an inert sentinel -- but note that the sentinel is
named for what it represents, because the fact that EVERY ADWS client
currently runs with a root-equivalent session is a known open issue
(see the authorization note in the read-side gap analysis, and
sambautils.py SamDBHelper.__init__).

When per-client identity is plumbed through from the GSSAPI negotiate,
this stub grows a corresponding user_session() and the tests will need
to assert which one a given request used.
"""


class SessionInfo(object):

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return 'SessionInfo(%r)' % self.name


def system_session():
    return SessionInfo('system')
