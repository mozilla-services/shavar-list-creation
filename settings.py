from configparser import ConfigParser, NoOptionError
import sys
import os
import math
from requests import auth
from packaging import version as p_version

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
environment = os.getenv("ENVIRONMENT", "dev")
if execution_environment != "JENKINS":
    ini_file = f"rs_{environment}.ini"

try:
    filenames = config.read(ini_file)
except Exception as e:
    print(f"Error reading .ini file: {e}!", file=sys.stderr)
    sys.exit(-1)

class SharedVersionNumbers:
    def __init__(self):
        self.latest_supported_version = -math.inf
        self.oldest_supported_version = math.inf

    def updateSupportedVersions(self, prod_list_branches, config):
        # make sure remote settings is enabled
        if config.get('main', 'remote_settings_upload') == False:
            return

        for branch in prod_list_branches:
            branch_name = branch.get('name')
            ver = p_version.parse(branch_name)

            if isinstance(ver, p_version.Version):
                if (ver.release[0] > self.latest_supported_version):
                    self.latest_supported_version = ver.release[0]

        self.oldest_supported_version = self.latest_supported_version - int(config.get('main', 'num_supported_versions'))

        print(f'\n\n The oldest supported version is {self.oldest_supported_version}\n')
        print(f'\n The latest supported version is {self.latest_supported_version}\n\n')

# initialize the shared variables
shared_state = SharedVersionNumbers()