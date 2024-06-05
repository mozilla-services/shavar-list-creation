from configparser import ConfigParser
import sys
import os

execution_environment = os.getenv("EXECUTION_ENVIRONMENT", "JENKINS")

config = ConfigParser(os.environ)
ini_file = "shavar_list_creation.ini"

if execution_environment == "GKE":
    environment = os.getenv("ENVIRONMENT", "stage")
    ini_file = f"rs_{environment}.ini"

filenames = config.read(ini_file)

if not filenames:
    print(f"Error reading .ini file!", file=sys.stderr)
    sys.exit(-1)
