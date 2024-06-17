from configparser import ConfigParser, NoOptionError
import sys
import os
from requests import auth

# Class to handle Bearer Token Authentication
class BearerAuth(auth.AuthBase):
    def __init__(self, token):
        self.token = token
    def __call__(self, r):
        r.headers["Authorization"] = self.token
        return r


# For local testing purposes, make sure to set RS_TESTING_ENVIRONMENT to True,
# ENVIRONMENT to "dev", and EXECUTION_ENVIRONMENT to "GKE"

execution_environment = os.getenv("EXECUTION_ENVIRONMENT", "JENKINS")
# One of "userpass" or "token"
rs_auth_method = os.getenv("REMOTE_SETTINGS_AUTH_METHOD", "userpass")

config = ConfigParser(os.environ)
ini_file = "shavar_list_creation.ini"

# For local testing and GKE environments we want to use the rs_*.ini file
if execution_environment != "JENKINS":
    environment = os.getenv("ENVIRONMENT", "dev")
    ini_file = f"rs_{environment}.ini"

try:
    filenames = config.read(ini_file)
except Exception as e:
    print(f"Error reading .ini file: {e}!", file=sys.stderr)
    sys.exit(-1)
