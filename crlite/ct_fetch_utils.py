# Python Standard Library
import base64
import binascii
from collections import Counter
from datetime import datetime
import os
import time

# 3rd-party libraries
from cryptography import x509
from cryptography.hazmat.backends import default_backend


counter = Counter()
CRL_distribution_points = set()


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

    print("All done. Process results: {}".format(counter))
    return CRL_distribution_points
