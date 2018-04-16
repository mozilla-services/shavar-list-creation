# Python Standard Library
import argparse
from datetime import datetime
from struct import pack
import sys

# 3rd-party libraries
import OpenSSL
import requests

# Local modules
from filter_cascade import FilterCascade
from ct_fetch_utils import processCTData


parser = argparse.ArgumentParser()
parser.add_argument("--path", required=True,
                    help="Path to folder on disk with CT certs from ct-fetch")
args = parser.parse_args()

certs_list = []


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
all_certs = []
revoked_certs = []


if not args.path:
    parser.print_usage()
    sys.exit(0)

CRL_distribution_points = processCTData(args.path)
print("CRL Distribution Points: %s" % CRL_distribution_points)

print("Fetching %s CRLs ..." % len(CRL_distribution_points))
for point in CRL_distribution_points:
    # Fetch and load the CRL
    resp = requests.get(point)
    crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, resp.content)

    # Export CRL as cryptography lib CRL
    crl_for_cryptography = crl.to_cryptography()

    # Get the CRL issuer certificate
    # Get the CRL issuer public signing key
    # Validate the CRL against the CRL issuer public signing key

    revocations_tuple = crl.get_revoked()
    for revocation in revocations_tuple:
        revoked_certs.append(revocation)

print("%s revoked certs." % len(revoked_certs))
mlbf_file_version = datetime.utcnow().strftime('%Y%m%d%H%M%S')

MLBF_FILENAME = 'moz-crlite-mlbf-%s' % mlbf_file_version

for idx, c in enumerate(certs_list):
    print "Iteration %i" % idx
    print c
    if idx == 500:
        break
    # let's say every third cert should *not* be in the filter
    shouldBeRevoked = (idx % 3 == 1)
    if shouldBeRevoked:
        # print "Appending %s to revoked list." % c
        all_certs.append(c["parsed.fingerprint_sha256"])
    else:
        # print "Appending %s to okay list." % c
        revoked_certs.append(c["parsed.fingerprint_sha256"])

cascade = FilterCascade(500, 1.3, 0.77, 1)
cascade.initialize(all_certs, revoked_certs)
cascade.check(all_certs, revoked_certs)

print("This filter cascade uses %d layers and %d bits" % (
    cascade.layerCount(),
    cascade.bitCount())
)
print("Writing to file %s" % MLBF_FILENAME)

mlbf_file = open(MLBF_FILENAME, 'w')
mlbf_file.write(pack('s', mlbf_file_version))

cascade.tofile(mlbf_file)
