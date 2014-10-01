#!/usr/bin/python

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib2
import urlparse

import boto.s3.connection
import boto.s3.key

parser = argparse.ArgumentParser(
  description="Generate digest256 list from disconnect",
  formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--disconnect_url",
  help="The location of the Disconnect list",
  default="http://services.disconnect.me/disconnect-plaintext.json")
parser.add_argument("--allowlist_url",
  default="https://raw.githubusercontent.com/mozilla-services/" +
          "shavar-list-exceptions/master/allow_list",
  help="The location of the allowlist")
parser.add_argument("--output_file",
  default="mozpub-track-digest256",
  help="The location of the output digest256 list")
parser.add_argument("--s3_url",
  default="",
  help="The bucket to which to upload the output digest256 list, e.g. s3://mmc-shavar")
# Unfortunately the support for boolean arguments in argparse is somewhat
# limited. Be safe and manually set one of two flags instead of relying on type
# conversion.
group = parser.add_mutually_exclusive_group()
group.add_argument("--s3_upload", dest="s3_upload", action="store_true",
  help="Upload to S3")
group.add_argument("--no_s3_upload", dest="s3_upload", action="store_false",
  help="Don't upload to S3")
group.set_defaults(s3_upload=False)

# bring a URL to canonical form as described at 
# https://developers.google.com/safe-browsing/developers_guide_v2
def canonicalize(d):
  if (not d or d == ""): 
    return d;

  # remove tab (0x09), CR (0x0d), LF (0x0a)
  d = re.subn("\t|\r|\n", "", d)[0];

  # remove any URL fragment
  fragment_index = d.find("#")
  if (fragment_index != -1):
    d = d[0:fragment_index]

  # repeatedly unescape until no more hex encodings
  while (1):
    _d = d;
    d = urllib2.unquote(_d);
    # if decoding had no effect, stop
    if (d == _d):
      break;

  # extract hostname (scheme://)(username(:password)@)hostname(:port)(/...)
  # extract path
  url_components = re.match(
    re.compile(
      "^(?:[a-z]+\:\/\/)?(?:[a-z]+(?:\:[a-z0-9]+)?@)?([^\/^\?^\:]+)(?:\:[0-9]+)?(\/(.*)|$)"), d);
  host = url_components.group(1);
  path = url_components.group(2) or "";
  path = re.subn("^(\/)+", "", path)[0];

  # remove leading and trailing dots
  host = re.subn("^\.+|\.+$", "", host)[0];
  # replace consequtive dots with a single dot
  host = re.subn("\.+", ".", host)[0];
  # lowercase the whole thing
  host = host.lower();

  # percent-escape any characters <= ASCII 32, >= 127, or '#' or '%'
  _path = "";
  for i in path:
    if (ord(i) <= 32 or ord(i) >= 127 or i == '#' or i == '%'):
      _path += urllib2.quote(i);
    else:
      _path += i;

  # Note: we do NOT append the scheme
  # because safebrowsing lookups ignore it
  return host + "/" + _path;

def find_hosts(disconnect_json, allow_list, chunk, output_file, log_file):
  """Finds hosts that we should block from the Disconnect json.

  Args:
    disconnect_json: A JSON blob containing Disconnect's list.
    allow_list: Hosts that we can't put on the blocklist.
    chunk: The chunk number to use.
    output_file: A file-handle to the output file.
    log_file: A filehandle to the log file.
  """
  # Total number of bytes, 0 % 32
  hashdata_bytes = 0;

  # Remember previously-processed domains so we don't print them more than once
  domain_dict = {};

  # Array holding hash bytes to be written to f_out. We need the total bytes
  # before writing anything.
  output = [];

  categories = disconnect_json["categories"]

  for c in categories:
    # Skip content and Legacy categories
    if c.find("Content") != -1 or c.find("Legacy") != -1:
      continue
    log_file.write("Processing %s\n" % c)

    # Objects of type
    # { Automattic: { http://automattic.com: [polldaddy.com] }}
    # Domain lists may or may not contain the address of the top-level site.
    for org in categories[c]:
      for orgname in org:
        top_domains = org[orgname]
        for top in top_domains:
          domains = top_domains[top]
          for d in domains:
            d = d.encode('utf-8');
            canon_d = canonicalize(d);
            if (not canon_d in domain_dict) and (not d in allow_list):
              log_file.write("[m] %s >> %s\n" % (d, canon_d));
              log_file.write("[canonicalized] %s\n" % (canon_d));
              log_file.write("[hash] %s\n" % hashlib.sha256(canon_d).hexdigest());
              domain_dict[canon_d] = 1;
              hashdata_bytes += 32;
              output.append(hashlib.sha256(canon_d).digest());

  # Write safebrowsing-list format header
  output_file.write("a:%u:32:%s\n" % (chunk, hashdata_bytes));
  output_string = "a:%u:32:%s\n" % (chunk, hashdata_bytes);
  for o in output:
    output_file.write(o);
    output_string = output_string + o
  return output_string


def main():
  args = parser.parse_args()
  try:
    disconnect_json = json.loads(urllib2.urlopen(args.disconnect_url).read())
  except:
    f_log.write("Error loading %s\n", args.disconnect_url)
    sys.exit(-1)

  output_file = open(args.output_file, "wb")
  log_file = open(args.output_file + ".log", "w")
  chunk = time.time()

  # load our allowlist
  allowed = set()
  if args.allowlist_url:
    for line in urllib2.urlopen(args.allowlist_url).readlines():
      line = line.strip()
      # don't add blank lines or comments
      if not line or line.startswith('#'):
        continue
      allowed.add(line)

  output_string = find_hosts(disconnect_json, allowed, chunk, output_file, log_file)

  output_file.close()
  log_file.close()

  # Optionally upload to S3. Both the S3 url and s3_upload arguments must be set.
  if args.s3_upload and args.s3_url:
    conn = boto.s3.connection.S3Connection()
    url = urlparse.urlparse(args.s3_url)
    bucket = conn.get_bucket(url.netloc)
    k = boto.s3.key.Key(bucket)
    k.key = args.output_file
    k.set_contents_from_string(output_string)
    print "Uploaded to s3"
  else:
    print "Skipping upload"

if __name__ == "__main__":
  main()
