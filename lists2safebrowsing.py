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

import boto.s3.connection
import boto.s3.key

from publicsuffixlist import PublicSuffixList
from publicsuffixlist.update import updatePSL

from disconnect_mapping import disconnect_mapping

updatePSL()
psl = PublicSuffixList()

PLUGIN_SECTIONS = (
    "plugin-blocklist",
    "plugin-blocklist-experiment",
    "flash-blocklist",
    "flash-exceptions",
    "flash-allow",
    "flash-allow-exceptions",
    "flash-subdoc",
    "flash-subdoc-exceptions",
    "flashinfobar-exceptions"
)
WHITELIST_SECTIONS = (
    "entity-whitelist",
    "entity-whitelist-testing",
    "staging-entity-whitelist",
    "fastblock1-whitelist",
    "fastblock2-whitelist"
)
PRE_DNT_SECTIONS = (
    "tracking-protection",
    "tracking-protection-testing",
    "tracking-protection-standard",
    "tracking-protection-full",
    "staging-tracking-protection-standard",
    "staging-tracking-protection-full",
    "fanboy-annoyance",
    "fanboy-social",
    "easylist",
    "easyprivacy",
    "adguard",
)
PRE_DNT_CONTENT_SECTIONS = (
    "tracking-protection-full",
    "staging-tracking-protection-full"
)
DNT_SECTIONS = (
    "tracking-protection-base",
    "tracking-protection-baseeff",
    "tracking-protection-basew3c",
    "tracking-protection-content",
    "tracking-protection-contenteff",
    "tracking-protection-contentw3c",
    "tracking-protection-ads",
    "tracking-protection-analytics",
    "tracking-protection-social",
    "tracking-protection-base-fingerprinting",
    "tracking-protection-content-fingerprinting",
    "tracking-protection-base-cryptomining",
    "tracking-protection-content-cryptomining",
    "tracking-protection-test-multitag",
    "fastblock1",
    "fastblock2",
    "fastblock3"
)
DNT_CONTENT_SECTIONS = (
    "tracking-protection-content",
    "tracking-protection-contenteff",
    "tracking-protection-contentw3c"
)
DNT_BLANK_SECTIONS = (
    "tracking-protection-base",
    "tracking-protection-content",
)
DNT_EFF_SECTIONS = (
    "tracking-protection-baseeff",
    "tracking-protection-contenteff",
)
DNT_W3C_SECTIONS = (
    "tracking-protection-basew3c",
    "tracking-protection-contentw3c"
)
FASTBLOCK_SECTIONS = (
    "fastblock1",
    "fastblock1-whitelist",
    "fastblock2",
    "fastblock2-whitelist",
    "fastblock3"
)

FINGERPRINTING_TAG = 'fingerprinting'
CRYPTOMINING_TAG = 'cryptominer'
SESSION_REPLAY_TAG = 'session-replay'
PERFORMANCE_TAG = 'performance'
ALL_TAGS = {
    FINGERPRINTING_TAG,
    CRYPTOMINING_TAG,
    SESSION_REPLAY_TAG,
    PERFORMANCE_TAG
}

DEFAULT_DISCONNECT_LIST_CATEGORIES = 'Advertising,Analytics,Social,Disconnect'
DEFAULT_DISCONNECT_LIST_TAGS = {""}


def get_output_and_log_files(config, section):
    output_file = None
    log_file = None
    output_filename = config.get(section, "output")
    if output_filename:
        output_file = open(output_filename, "wb")
        log_file = open(output_filename + ".log", "w")
    return output_file, log_file


def load_json_from_url(config, section, key):
    try:
        url = config.get(section, key)
    except ConfigParser.NoOptionError:
        url = config.get("main", "default_disconnect_url")
    try:
        loaded_json = json.loads(urllib2.urlopen(url).read())
    except:
        sys.stderr.write("Error loading %s\n" % url)
        sys.exit(-1)
    return loaded_json


# bring a URL to canonical form as described at
# https://web.archive.org/web/20160422212049/https://developers.google.com/safe-browsing/developers_guide_v2#Canonicalization
def canonicalize(d):
  if (not d or d == ""):
    return d;

  # remove tab (0x09), CR (0x0d), LF (0x0a)
  # TODO?: d, _subs_made = re.subn("\t|\r|\n", "", d)
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
  # TODO?: use urlparse ?
  url_components = re.match(
    re.compile(
      "^(?:[a-z]+\:\/\/)?(?:[a-z]+(?:\:[a-z0-9]+)?@)?([^\/^\?^\:]+)(?:\:[0-9]+)?(\/(.*)|$)"), d);
  host = url_components.group(1);
  path = url_components.group(2) or "";
  path = re.subn("^(\/)+", "", path)[0];

  # remove leading and trailing dots
  # TODO?: host, _subs_made = re.subn("^\.+|\.+$", "", host)
  host = re.subn("^\.+|\.+$", "", host)[0];
  # replace consequtive dots with a single dot
  # TODO?: host, _subs_made = re.subn("\.+", ".", host)
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


# TODO?: rename find_tracking_hosts
def find_hosts(blocklist_json, allow_list, chunk, output_file, log_file,
               which_dnt, list_categories, name, desired_tags):
  """Finds hosts that we should block from the Disconnect json.

  Args:
    blocklist_json: A JSON blob containing Disconnect's list.
    allow_list: Hosts that we can't put on the blocklist.
    chunk: The chunk number to use.
    output_file: A file-handle to the output file.
    log_file: A filehandle to the log file.
    which_dnt: A filter to restrict output to section of the list with the
        specified DNT tag.
    list_categories : A filter to restrict output to the specified top-level
        categories.
    name : The section name from `shavar_list_creation.ini`
    desired_tags : A filter to restrict output to sections of the list with the
        specified sub-category tags.
  """
  # Number of items published
  publishing = 0

  # Total number of bytes, 0 % 32
  hashdata_bytes = 0;

  # Remember previously-processed domains so we don't print them more than once
  # TODO?: domain_dict = []
  domain_dict = {};

  # Array holding hash bytes to be written to f_out. We need the total bytes
  # before writing anything.
  output = [];

  categories = blocklist_json["categories"]

  for c in categories:
    add_category_to_list = False
    for lc in list_categories.split(","):
      if c.find(lc) != -1:
          add_category_to_list = True
    if not add_category_to_list:
      continue
    if add_category_to_list:
      # Is this list a single-category list?
      if len(list_categories) == 1:
        # Reset output to only include this category's content
        output = []
    if log_file:
      log_file.write("Processing %s\n" % c)

    # Objects of type
    # { Automattic: { http://automattic.com: [polldaddy.com] }}
    # Domain lists may or may not contain the address of the top-level site.
    for org in categories[c]:
      for orgname in org:
        org_json = org[orgname]

        # Skip organization if it doesn't have the desired dnt annotation
        dnt_value = org_json.pop('dnt', '')
        assert dnt_value in ["w3c", "eff", ""]
        if dnt_value != which_dnt:
            continue

        # Skip organization if it doesn't have the desired sub-category tag
        observed_tags = {""}
        for tag in ALL_TAGS:
            tag_value = org_json.pop(tag, '')
            assert tag_value in ["true", ""]
            if tag_value == "":
                continue
            observed_tags.add(tag)
        if len(desired_tags.intersection(observed_tags)) == 0:
            continue

        for top in org_json:
          domains = org_json[top]
          for d in domains:
            d = d.encode('utf-8');
            if c == "Disconnect":
                try:
                    if not disconnect_mapping[d] in list_categories:
                        continue
                except KeyError:
                    sys.stderr.write(
                        "[ERROR] %s not found in disconnect_mapping\n" % d
                    )
            canon_d = canonicalize(d);
            if (not canon_d in domain_dict) and (not d in allow_list):
              # check if the domain is in the public suffix list
              # SafeBrowsing keeps trailing '/', PublicSuffix does not
              psl_d = canon_d.rstrip('/')
              if psl.publicsuffix(psl_d) == psl_d:
                if log_file:
                  log_file.write("[Public Suffix] %s; Skipping.\n" % psl_d)
                continue
              if log_file:
                log_file.write("[m] %s >> %s\n" % (d, canon_d));
                log_file.write("[canonicalized] %s\n" % (canon_d));
                log_file.write("[hash] %s\n" % hashlib.sha256(canon_d).hexdigest());
              publishing += 1
              domain_dict[canon_d] = 1;
              # TODO?: hashdata_bytes += hashdata.digest_size
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

  if (name in FASTBLOCK_SECTIONS): 
    print "Fastblock(%s): publishing %d items; file size %d" % (name, publishing, len(output_string))
  else:
    print "Tracking protection(%s): publishing %d items; file size %d" \
            % (name, publishing, len(output_string))
  return output_string

def process_entity_whitelist(incoming, chunk, output_file,
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
  if(list_variant in FASTBLOCK_SECTIONS):
    print "Fastblock whitelist(%s): publishing %d items; file size %d" % (list_variant, publishing, output_size)
  else:
    print "Entity whitelist(%s): publishing %d items; file size %d" \
            % (list_variant, publishing, output_size)

def process_plugin_blocklist(incoming, chunk, output_file, log_file,
                             list_variant):
  publishing = 0
  domains = set()
  hashdata_bytes = 0
  output = []
  for d in incoming:
    canon_d = canonicalize(d.encode('utf-8'))
    if canon_d not in domains:
      h = hashlib.sha256(canon_d)
      if log_file:
        log_file.write("[plugin-blocklist] %s >> (canonicalized) %s, hash %s\n"
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
  print "Plugin blocklist(%s): publishing %d items; file size %d" \
           % (list_variant, publishing, output_size)

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

  chunknum = int(time.time())

  for section in config.sections():
    if section == "main":
      continue

    if (section in PRE_DNT_SECTIONS or section in DNT_SECTIONS):
      if (section in FASTBLOCK_SECTIONS):
        # process fastblock
        blocklist_json = load_json_from_url(config, section, "blocklist_url")
      else:
        # process disconnect
        blocklist_json = load_json_from_url(config, section, "disconnect_url")

      output_file, log_file = get_output_and_log_files(config, section)

      # load our allowlist
      allowed = set()
      try:
        allowlist_url = config.get(section, "allowlist_url")
      except:
        allowlist_url = None
      # TODO: refactor into: def get_allowed_domains(allowlist_url)
      if allowlist_url:
        for line in urllib2.urlopen(allowlist_url).readlines():
          line = line.strip()
          # don't add blank lines or comments
          if not line or line.startswith('#'):
            continue
          allowed.add(line)

      try:
        list_categories = config.get(section, "disconnect_categories")
      except ConfigParser.NoOptionError:
        list_categories = DEFAULT_DISCONNECT_LIST_CATEGORIES

      if section in DNT_EFF_SECTIONS:
          which_dnt = "eff"
      elif section in DNT_W3C_SECTIONS:
          which_dnt = "w3c"
      else:
          which_dnt = ""

      try:
          desired_tags = set(config.get(section, "disconnect_tags").split(','))
          if len(desired_tags.difference(ALL_TAGS)) > 0:
              raise ValueError(
                  "The configuration file contains unsupported tags.\n"
                  "Supported tags: %s\nConfig file tags: %s" %
                  (ALL_TAGS, desired_tags)
              )
      except ConfigParser.NoOptionError:
          desired_tags = DEFAULT_DISCONNECT_LIST_TAGS

      find_hosts(blocklist_json, allowed, chunknum, output_file, log_file,
                 which_dnt, list_categories, section, desired_tags)

    if section in PLUGIN_SECTIONS:
      output_file, log_file = get_output_and_log_files(config, section)

      # load the plugin blocklist
      blocked = set()
      blocklist_url = config.get(section, "blocklist")
      if blocklist_url:
        for line in urllib2.urlopen(blocklist_url).readlines():
          line = line.strip()
          # don't add blank lines or comments
          if not line or line.startswith('#'):
            continue
          blocked.add(line)

      process_plugin_blocklist(blocked, chunknum, output_file, log_file,
                               section)

    if section in WHITELIST_SECTIONS:
      output_file, log_file = get_output_and_log_files(config, section)

      # download and load the business entity oriented whitelist
      whitelist = load_json_from_url(config, section, "entity_url")

      process_entity_whitelist(whitelist, chunknum,
                                          output_file, log_file,
                                          section)

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

    chunk_key = os.path.join(config.get(section, os.path.basename('output')),
                             str(chunknum))

    if not bucket or not key:
      sys.stderr.write("Can't upload to s3 without s3_bucket and s3_key\n")
      sys.exit(-1)

    output_filename = config.get(section, "output")
    conn = boto.s3.connection.S3Connection()
    bucket = conn.get_bucket(bucket)
    for key_name in (chunk_key, key):
      k = boto.s3.key.Key(bucket)
      k.key = key_name
      k.set_contents_from_filename(output_filename)
    print "Uploaded to s3: %s" % section


if __name__ == "__main__":
  main()
