#!/usr/bin/env python

import ConfigParser
import hashlib
import json
import os
import re
import sys
import tempfile
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

def find_hosts(disconnect_json, allow_list, chunk, output_file, log_file,
               add_content_category=False, name="prod"):
  """Finds hosts that we should block from the Disconnect json.

  Args:
    disconnect_json: A JSON blob containing Disconnect's list.
    allow_list: Hosts that we can't put on the blocklist.
    chunk: The chunk number to use.
    output_file: A file-handle to the output file.
    log_file: A filehandle to the log file.
  """
  # Number of items published
  publishing = 0

  # Total number of bytes, 0 % 32
  hashdata_bytes = 0;

  # Remember previously-processed domains so we don't print them more than once
  domain_dict = {};

  # Array holding hash bytes to be written to f_out. We need the total bytes
  # before writing anything.
  output = [];

  categories = disconnect_json["categories"]

  for c in categories:
    # Skip content and Legacy categories as necessary
    if c.find("Legacy") != -1:
      continue
    if (c.find("Content") != -1 and not add_content_category):
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
              publishing += 1
              domain_dict[canon_d] = 1;
              hashdata_bytes += 32;
              output.append(hashlib.sha256(canon_d).digest());

  # Write safebrowsing-list format header
  if output_file:
    output_file.write("a:%u:32:%s\n" % (chunk, hashdata_bytes));
  output_string = "a:%u:32:%s\n" % (chunk, hashdata_bytes);
  for o in output:
    if output_file:
      output_file.write(o);
    output_string = output_string + o

  print "Tracking protection(%s): publishing %d items; file size %d" \
           % (name, publishing, len(output_string))
  return output_string

def process_disconnect_entity_whitelist(incoming, chunk, output_file,
                                        log_file, list_variant):
  """
  Expects a dict from a loaded JSON blob.
  """
  publishing = 0
  urls = set()
  hashdata_bytes = 0
  output = []
  for name, entity in sorted(incoming.items()):
    name = name.encode('utf-8')
    for prop in entity['properties']:
      for res in entity['resources']:
        prop = prop.encode('utf-8')
        res = res.encode('utf-8')
        if prop == res:
          continue
        d = canonicalize('%s/?resource=%s' % (prop, res))
        h = hashlib.sha256(d)
        if log_file:
          log_file.write("[entity] %s >> (canonicalized) %s, hash %s\n"
                         % (name, d, h.hexdigest()))
        urls.add(d)
        publishing += 1
        hashdata_bytes += 32
        output.append(hashlib.sha256(d).digest())

  # Write the data file
  output_file.write("a:%u:32:%s\n" % (chunk, hashdata_bytes))
  # FIXME: we should really sort the output
  for o in output:
    output_file.write(o)

  output_file.flush()
  output_size = os.fstat(output_file.fileno()).st_size
  print "Entity whitelist (%s): publishing %d items; file size %d" \
           % (list_variant, publishing, output_size)

def process_shumway(incoming, chunk, output_file, log_file):
  publishing = 0
  domains = set()
  hashdata_bytes = 0
  output = []
  for d in incoming:
    canon_d = canonicalize(d.encode('utf-8'))
    if canon_d not in domains:
      h = hashlib.sha256(canon_d)
      if log_file:
        log_file.write("[shumway] %s >> (canonicalized) %s, hash %s\n"
                       % (d, canon_d, h.hexdigest()))
      publishing += 1
      domains.add(canon_d)
      hashdata_bytes += 32
      output.append(hashlib.sha256(canon_d).digest())
  # Write the data file
  output_file.write("a:%u:32:%s\n" % (chunk, hashdata_bytes))
  # FIXME: we should really sort the output
  for o in output:
    output_file.write(o)

  output_file.flush()
  output_size = os.fstat(output_file.fileno()).st_size
  print "Shumway: publishing %d items; file size %d" \
           % (publishing, output_size)

def chunk_metadata(fp):
  # Read the first 25 bytes and look for a new line.  Since this is a file
  # formatted like a chunk, a end of the chunk header(a newline) should be
  # found early.
  header = fp.read(25)
  eoh = header.find('\n')
  chunktype, chunknum, hash_size, data_len = header[:eoh].split(':')
  return dict(type=chunktype, num=chunknum, hash_size=hash_size, len=data_len,
              checksum=hashlib.sha256(fp.read()).hexdigest())

def new_data_to_publish(config, section, blob):
  # Get the metadata for our old chunk

  # If necessary, fetch the existing data from S3, otherwise open a local file
  if ((config.has_option('main', 's3_upload')
      and config.getboolean('main', 's3_upload'))
       or (config.has_option(section, 's3_upload')
           and config.getboolean(section, 's3_upload'))):
    conn = boto.s3.connection.S3Connection()
    bucket = conn.get_bucket(config.get('main', 's3_bucket'))
    s3key = config.get(section, 's3_key') or config.get(section, 'output')
    key = bucket.get_key(s3key)
    if key is None:
      # most likely a new list
      print "{0} looks like it hasn't been uploaded to s3://{1}/{2}".format(section, bucket.name, s3key)
      key = boto.s3.key.Key(bucket)
      key.key = s3key
      key.set_contents_from_string("a:1:32:32\n" + 32 * '1')
    current = tempfile.TemporaryFile()
    key.get_contents_to_file(current)
    current.seek(0)
  else:
    current = open(config.get(section, 'output'), 'rb')

  old = chunk_metadata(current)
  current.close()

  new = chunk_metadata(blob)

  if old['checksum'] != new['checksum']:
    return True
  return False

def main():
  config = ConfigParser.ConfigParser()
  filename = config.read(["shavar_list_creation.ini"])
  if not filename:
    sys.stderr.write("Error loading shavar_list_creation.ini\n")
    sys.exit(-1)

  for section in config.sections():
    if section == "main":
      continue

    if section in ("tracking-protection", "tracking-protection-testing",
                   "tracking-protection-abtest"):
      # process disconnect
      disconnect_url = config.get(section, "disconnect_url")
      try:
        disconnect_json = json.loads(urllib2.urlopen(disconnect_url).read())
      except:
        sys.stderr.write("Error loading %s\n", disconnect_url)
        sys.exit(-1)

      output_file = None
      log_file = None
      output_filename = config.get(section, "output")
      if output_filename:
        output_file = open(output_filename, "wb")
        log_file = open(output_filename + ".log", "w")
      chunk = time.time()

      # load our allowlist
      allowed = set()
      allowlist_url = config.get(section, "allowlist_url")
      if allowlist_url:
        for line in urllib2.urlopen(allowlist_url).readlines():
          line = line.strip()
          # don't add blank lines or comments
          if not line or line.startswith('#'):
            continue
          allowed.add(line)

      content_category=False
      list_variant="prod"
      if section == "tracking-protection-testing":
        list_variant="testing"
      elif section == "tracking-protection-abtest":
        content_category=True
        list_variant="abtest"

      find_hosts(disconnect_json, allowed, chunk, output_file, log_file,
                 add_content_category=content_category, name=list_variant)

    if section == "shumway":
      output_file = None
      log_file = None
      output_filename = config.get(section, "output")
      if output_filename:
        output_file = open(output_filename, "wb")
        log_file = open(output_filename + ".log", "w")
      chunk = time.time()

      # load our allowlist
      allowed = set()
      allowlist_url = config.get(section, "whitelist")
      if allowlist_url:
        for line in urllib2.urlopen(allowlist_url).readlines():
          line = line.strip()
          # don't add blank lines or comments
          if not line or line.startswith('#'):
            continue
          allowed.add(line)

      process_shumway(allowed, chunk, output_file, log_file)

    if section in ("entity-whitelist", "entity-whitelist-testing"):
      output_file = None
      log_file = None
      output_filename = config.get(section, "output")
      if output_filename:
        output_file = open(output_filename, "wb")
        log_file = open(output_filename + ".log", "w")
      chunk = time.time()

      # download and load the business entity oriented whitelist
      entity_url = config.get(section, "entity_url")
      try:
        disconnect_json = json.loads(urllib2.urlopen(entity_url).read())
      except:
        sys.stderr.write("Error loading %s\n", entity_url)
        sys.exit(-1)

      list_variant="prod"
      if section == "entity-whitelist-testing":
        list_variant="testing"

      process_disconnect_entity_whitelist(disconnect_json, chunk, output_file,
                                          log_file, list_variant)

  if output_file:
    output_file.close()
  if log_file:
    log_file.close()

  # Optionally upload to S3. If s3_upload is set, then s3_bucket and s3_key
  # must be set.
  for section in config.sections():
    if section == 'main':
      continue

    with open(config.get(section, 'output'), 'rb') as blob:
      if not new_data_to_publish(config, section, blob):
        print "No new data to publish for %s" % section
        continue

    if (config.has_option(section, "s3_upload")
        and not config.getboolean(section, "s3_upload")):
      print "Skipping S3 upload for %s" % section
      continue

    bucket = config.get("main", "s3_bucket")
    # Override with list specific bucket if necessary
    if config.has_option(section, "s3_bucket"):
      bucket = config.get(section, "s3_bucket")

    key = os.path.basename(config.get(section, "output"))
    # Override with list specific value if necessary
    if config.has_option(section, "s3_key"):
      key = config.get(section, "s3_key")

    if not bucket or not key:
      sys.stderr.write("Can't upload to s3 without s3_bucket and s3_key\n")
      sys.exit(-1)

    output_filename = config.get(section, "output")
    conn = boto.s3.connection.S3Connection()
    bucket = conn.get_bucket(bucket)
    k = boto.s3.key.Key(bucket)
    k.key = key
    k.set_contents_from_filename(output_filename)
    print "Uploaded to s3: %s" % section


if __name__ == "__main__":
  main()
