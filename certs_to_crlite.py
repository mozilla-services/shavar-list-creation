# Python Standard Library
import argparse
import base64
import binascii
from collections import Counter
from datetime import datetime
import os
from struct import pack
import sys
import time

# 3rd-party libraries
import censys.certificates
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from decouple import config

# Local modules
from filter_cascade import FilterCascade


parser = argparse.ArgumentParser()
parser.add_argument("--path", help="Path to folder on disk with CT certs")
args = parser.parse_args()

counter = Counter()

CRL_distribution_points = set()

certs_list = []


"""
processCer, processPEM, getMetaDataCert, processFolder, processCTData
borrow generously from:
https://github.com/jcjones/ct-mapreduce/blob/ed586b1dc5e3a2263c09c611b1733a83fc18cab9/python/ct-mapreduce-map.py
"""


def processCer(file_path):
    """
    This method processes one single certificate, in DER-format
    """
    try:
        with open(file_path, 'rb') as f:
            der_data = f.read()
            cert = x509.load_der_x509_certificate(der_data, default_backend())
            crl_points = cert.extensions.get_extension_for_class(
                x509.CRLDistributionPoints
            )
            for point in crl_points.value:
                for name in point.full_name:
                    CRL_distribution_points.update([name.value])
                    counter["Total CRLs Processed"] += 1
            counter["Total DER Files Processed"] += 1
            counter["Total Certificates Processed"] += 1
    except ValueError as e:
        print("{}\t{}\n".format(file_path, e))
        counter["Certificate Parse Errors"] += 1


def processPem(path):
    """
    This method processes a PEM file which may contain one or more
    PEM-formatted certificates.
    """

    with open(path, 'r') as pemFd:
        counter["Total PEM Files Processed"] += 1
        pem_buffer = ""
        buffer_len = 0
        offset = 0

        for line in pemFd:
            # Record length always
            buffer_len += len(line)

            if line == "-----BEGIN CERTIFICATE-----\n":
                continue
            if (
                line.startswith("LogID") or
                line.startswith("Recorded-at") or
                len(line) == 0 or
                line.startswith("Seen-in-log")
               ):
                continue
            if line == "-----END CERTIFICATE-----\n":
                # process the PEM
                try:
                    der_data = base64.standard_b64decode(pem_buffer)
                    cert = x509.load_der_x509_certificate(
                        der_data, default_backend()
                    )
                    crl_points = cert.extensions.get_extension_for_class(
                        x509.CRLDistributionPoints
                    )
                    for point in crl_points.value:
                        for name in point.full_name:
                            CRL_distribution_points.update([name.value])
                            counter["Total CRLs Processed"] += 1
                except ValueError as e:
                    print("{}:{}\t{}\n".format(path, offset, e))
                    counter["Certificate Parse Errors"] += 1
                counter["Total Certificates Processed"] += 1

                # clear the buffer
                pem_buffer = ""
                offset += buffer_len
                buffer_len = 0
                continue

            # Just a normal part of the base64, so add it to the buffer
            pem_buffer += line


def getMetadataForCert(aCert):
    metaData = {}
    fqdns = set()

    # Issuance date, organization, and AKI are all required
    try:
        metaData["issuedate"] = aCert.not_valid_before.date().isoformat()
        metaData["issuer"] = aCert.issuer.get_attributes_for_oid(
            x509.oid.NameOID. ORGANIZATION_NAME
        )[0].value

        akiext = aCert.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        )
        metaData["aki"] = binascii.hexlify(
            akiext.value.key_identifier
        ).decode('utf8')

        spki = aCert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )
        metaData["spki"] = binascii.hexlify(spki.value.digest).decode('utf8')

        # Get the FQDNs
        subject = aCert.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )[0]
        fqdns.add(subject.value)

    except x509.extensions.ExtensionNotFound as e:
        raise ValueError(e)

    try:
        san = aCert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        fqdns.update(san.value.get_values_for_type(x509.DNSName))
    except:
        # SANs are optional, sorta.
        pass

    # Filter out wildcards
    metaData["fqdns"] = ",".join(
        set(filter(lambda x: x.startswith("*.") is False, fqdns))
    )

    # Get the registered domains
    """
    I don't think we need this for crlite
    regdoms = set()
    for fqdn in fqdns:
        regdoms.add(aPsl.suffix(fqdn) or fqdn)
        metaData["regdoms"] = ",".join(regdoms)
        """

    return metaData


def processFolder(path):
    file_queue = []

    # print("Folder {} processing".format(path))

    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith("cer") or file.endswith("pem"):
                file_queue.append(os.path.join(root, file))

    for file_path in file_queue:
        if file_path.endswith("cer"):
            processCer(file_path)
        elif file_path.endswith("pem"):
            processPem(file_path)
        else:
            raise Exception("Unknown type " + file_path)

    # print("Folder {} complete".format(path))

    counter["Folders Processed"] += 1


def processCTData(path):
    for item in os.listdir(path):
        if item == "state":
            continue

        entry = os.path.join(path, item)
        if not os.path.isdir(entry):
            continue

        # Is this expired (check by looking the path so we don't have to
        # continue to load)
        pathdate = datetime.strptime(item, "%Y-%m-%d").timetuple()
        now = time.gmtime()
        expired_by_year = pathdate.tm_year < now.tm_year
        expired_by_yday = (
            pathdate.tm_year == now.tm_year and pathdate.tm_yday < now.tm_yday
        )
        if expired_by_year or expired_by_yday:
            counter["Folders Expired"] += 1
            continue

        processFolder(entry)
        counter["Folders Up-to-date"] += 1


CENSYS_API_UID = config("CENSYS_API_UID", None)
CENSYS_API_SECRET = config("CENSYS_API_SECRET", None)

if not CENSYS_API_UID or not CENSYS_API_SECRET:
    print "Must set CENSYS_API_UID and CENSYS_API_SECRET"
    sys.exit(1)

certificates = censys.certificates.CensysCertificates(
    CENSYS_API_UID, CENSYS_API_SECRET
)

"""
certs_list = certificates.search(
    'parsed.issuer.organization.raw: "DigiCert Inc"',
    fields=[
        "parsed.fingerprint_sha256",
        "parsed.extensions.crl_distribution_points",
        "parsed.extensions.crl_distribution_points.raw",
    ]
)
"""


if not args.path:
    parser.print_usage()
    sys.exit(0)

crls = processCTData(args.path)
print("All done. Process results: {}".format(counter))
print("CRL Distribution Points: %s" % CRL_distribution_points)

mlbf_file_version = datetime.utcnow().strftime('%Y%m%d%H%M%S')

MLBF_FILENAME = 'moz-crlite-mlbf-%s' % mlbf_file_version

all_certs = []
revoked_certs = []

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
