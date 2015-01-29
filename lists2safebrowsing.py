#!/usr/bin/python

import ConfigParser
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
    if log_file:
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
              if log_file:
                log_file.write("[m] %s >> %s\n" % (d, canon_d));
                log_file.write("[canonicalized] %s\n" % (canon_d));
                log_file.write("[hash] %s\n" % hashlib.sha256(canon_d).hexdigest());
              domain_dict[canon_d] = 1;
              hashdata_bytes += 32;
              output.append(hashlib.sha256(canon_d).digest());

  # Write safebrowsing-list format header
  if output_file:
    output_file.write("ad:1-%u\n" % (chunk - 1))
    output_file.write("a:%u:32:%s\n" % (chunk, hashdata_bytes))
  output_string = "ad:1-%u\n" % (chunk-1)
  output_string = output_string + "a:%u:32:%s\n" % (chunk, hashdata_bytes);
  for o in output:
    if output_file:
      output_file.write(o);
    output_string = output_string + o
  return output_string


def main():
  config = ConfigParser.ConfigParser()
  filename = config.read(["shavar_list_creation.ini"])
  if not filename:
    sys.stderr.write("Error loading shavar_list_creation.ini\n")
    sys.exit(-1)

  disconnect_url = config.get("ShavarListCreation", "disconnect_url")
  try:
    disconnect_json = json.loads(urllib2.urlopen(disconnect_url).read())
  except:
    sys.stderr.write("Error loading %s\n", disconnect_url)
    sys.exit(-1)

  output_file = None
  log_file = None
  output_filename = config.get("ShavarListCreation", "output_file")
  if output_filename:
    output_file = open(output_filename, "wb")
    log_file = open(output_filename + ".log", "w")
  chunk = time.time()

  # load our allowlist
  allowed = set()
  allowlist_url = config.get("ShavarListCreation", "allowlist_url")
  if allowlist_url:
    for line in urllib2.urlopen(allowlist_url).readlines():
      line = line.strip()
      # don't add blank lines or comments
      if not line or line.startswith('#'):
        continue
      allowed.add(line)

  output_string = find_hosts(disconnect_json, allowed, chunk, output_file, log_file)

  if output_file:
    output_file.close()
  if log_file:
    log_file.close()

  # Optionally upload to S3. If s3_upload is set, then s3_bucket and s3_key
  # must be set.
  if config.getboolean("ShavarListCreation", "s3_upload"):
    bucket = config.get("ShavarListCreation", "s3_bucket")
    key = config.get("ShavarListCreation", "s3_key")
    if not bucket or not key:
      sys.stderr.write("Can't upload to s3 without s3_bucket and s3_key\n")
      sys.exit(-1)

    conn = boto.s3.connection.S3Connection()
    bucket = conn.get_bucket(bucket)
    k = boto.s3.key.Key(bucket)
    k.key = key
    k.set_contents_from_string(output_string)
    print "Uploaded to s3"
  else:
    print "Skipping upload"

if __name__ == "__main__":
  main()
