# Python Standard Library
from datetime import datetime
import json
from struct import pack

# Local modules
from filter_cascade import FilterCascade


"""
CENSYS_API_UID = config("CENSYS_API_UID", None)
CENSYS_API_SECRET = config("CENSYS_API_SECRET", None)

if not CENSYS_API_UID or not CENSYS_API_SECRET:
    print "Must set CENSYS_API_UID and CENSYS_API_SECRET"
    sys.exit(1)

certificates = censys.certificates.CensysCertificates(
    CENSYS_API_UID, CENSYS_API_SECRET
)

certs_list = certificates.search(
    'parsed.issuer.organization.raw: "DigiCert Inc"',
    fields=[
        "parsed.fingerprint_sha256",
        "parsed.extensions.crl_distribution_points",
        "parsed.extensions.crl_distribution_points.raw",
    ]
)
"""
nonrevoked_certs_file = open('final_crl_nonrevoked.json')
revoked_certs_file = open('final_crl_revoked.json')

nonrevoked_certs = []
revoked_certs = []


print("%s revoked certs." % len(revoked_certs))
mlbf_file_version = datetime.utcnow().strftime('%Y%m%d%H%M%S')

MLBF_FILENAME = 'moz-crlite-mlbf-%s' % mlbf_file_version

for line in nonrevoked_certs_file:
    cert = json.loads(line)
    nonrevoked_certs.append(str(cert['serial_number']))

for line in revoked_certs_file:
    cert = json.loads(line)
    revoked_certs.append(str(cert['serial_number']))


cascade = FilterCascade(70000, 1.3, 0.77, 1)
cascade.initialize(nonrevoked_certs, revoked_certs)
cascade.check(nonrevoked_certs, revoked_certs)

print("This filter cascade uses %d layers and %d bits" % (
    cascade.layerCount(),
    cascade.bitCount())
)
print("Writing to file %s" % MLBF_FILENAME)

mlbf_file = open(MLBF_FILENAME, 'w')
mlbf_file.write(pack('s', mlbf_file_version))

cascade.tofile(mlbf_file)
