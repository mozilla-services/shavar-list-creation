#!/usr/bin/python
"""Create a host list from the given disconnect repo."""
# Usage: disconnect.py <input_json> <output_file>

import os
import re
import sys

import hashlib

import urllib2

import json

# book-keeping dictionary. 
# remembers previously-processed domains 
# so we don't print them more than once
domain_dict = {};

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


def find_hosts(filename, f_out, f_log, chunk, allow_list):
  f_in = open(filename, "r")

  # total number of bytes that will be written to f_out for hashed hosts 
  # should be modulo 32
  hashdata_bytes = 0;

  # array holding hash bytes to be written to f_out.
  # we buffer output here because we need to know the 
  # final byte first (see hashdata_bytes)
  output = [];
  output_dbg = [];

  blob = json.loads(f_in.read())

  categories = blob["categories"]

  for c in categories:
    # Skip content and Legacy categories
    if c.find("Content") != -1 or c.find("Legacy") != -1:
      continue
    f_log.write("Processing %s\n" % c)

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
              f_log.write("[m] %s >> %s\n" % (d, canon_d));
              f_log.write("[canonicalized] %s\n" % (canon_d));
              f_log.write("[hash] %s\n" % hashlib.sha256(canon_d).hexdigest());
              domain_dict[canon_d] = 1;
              hashdata_bytes += 32;
              try:
                output_dbg.append(hashlib.sha256(canon_d).hexdigest());
                output.append(hashlib.sha256(canon_d).digest());
              except:
                f_log.write("error processing " + json.dumps(d) + "\n")

  # write safebrowsing-list format header
  f_out.write("a:%u:32:%s\n" % (chunk, hashdata_bytes));

  for o in output:
    f_out.write(o);


def main(dir, f_out, f_log, chunk, allow_list=[]):
  for root, dirs, files in os.walk(dir):
    # Process all of the files, one by one
    if root.find(".hg") != -1:
      continue
    for name in files:
      find_hosts(os.path.join(root, name), f_out, f_log, chunk,
                 allow_list);
      chunk += 1;

  return chunk;
