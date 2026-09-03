"""
------------------------------------------------------------------------------
Script Name:      tests/stubs/samba/__init__.py
Script Author:    Neal Russell
Script Created:   2026-09-03
Script Version:   1.0.0
Script Purpose:   Stand-in for the `samba` package so sambautils.py can be
                  imported without a Samba installation.

Script Desc:      sambautils.py imports four things from this package:
                    from samba.samdb import SamDB
                    from samba.param import LoadParm
                    from samba.auth  import system_session
                    from samba       import dsdb
                  Each has a counterpart module in this directory. The
                  real work happens in samdb.py, which routes every
                  directory call to a pluggable backend supplied by the
                  test (see tests/replay.py).
------------------------------------------------------------------------------
Execution Context: Installed into sys.modules by tests/conftest.py before
                   sambautils is imported. Never used in production.
------------------------------------------------------------------------------
"""

__version__ = 'stub'
