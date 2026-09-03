"""
Stand-in for samba.param.

SamDBHelper.__init__ constructs a LoadParm and calls load_default() to
locate smb.conf. Under test there is no smb.conf, so this records the
call and does nothing else.
"""


class LoadParm(object):

    def __init__(self, *args, **kwargs):
        self.loaded_default = False

    def load_default(self):
        self.loaded_default = True

    def load(self, path):
        self.loaded_default = True

    def get(self, name, default=None):
        return default
