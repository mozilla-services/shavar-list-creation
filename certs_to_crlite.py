import datetime
from struct import pack
import sys

import censys.certificates
from decouple import config
from filter_cascade import FilterCascade

CENSYS_API_UID = config("CENSYS_API_UID", None)
CENSYS_API_SECRET = config("CENSYS_API_SECRET", None)

if not CENSYS_API_UID or not CENSYS_API_SECRET:
    print "Must set CENSYS_API_UID and CENSYS_API_SECRET"
    sys.exit(1)

certificates = censys.certificates.CensysCertificates(
    CENSYS_API_UID, CENSYS_API_SECRET
)

mlbf_file_version = datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')

MLBF_FILENAME = 'moz-crlite-mlbf-%s' % mlbf_file_version

a = []
b = []

certs_list = certificates.search(
    'parsed.issuer.organization.raw: "DigiCert Inc"'
)

for idx, c in enumerate(certs_list):
    print "Iteration %i" % idx
    if idx == 500:
        break
    # let's say every third cert should *not* be in the filter
    shouldBeRevoked = (idx % 3 == 1)
    if shouldBeRevoked:
        # print "Appending %s to revoked list." % c
        a.append(c["parsed.fingerprint_sha256"])
    else:
        # print "Appending %s to okay list." % c
        b.append(c["parsed.fingerprint_sha256"])

cascade = FilterCascade(500, 1.3, 0.77, 1)
cascade.initialize(a, b)
cascade.check(a, b)

print("This filter cascade uses %d layers and %d bits" % (
    cascade.layerCount(),
    cascade.bitCount())
)
print("Writing to file %s" % MLBF_FILENAME)

mlbf_file = open(MLBF_FILENAME, 'w')
mlbf_file.write(pack('s', mlbf_file_version))

cascade.tofile(mlbf_file)
