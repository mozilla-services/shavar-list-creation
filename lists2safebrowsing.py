#!/usr/bin/env python

import ConfigParser
import hashlib
import json
import os
import re
import requests
import sys
import time
import urllib2

from packaging import version
from publicsuffixlist import PublicSuffixList
from publicsuffixlist.update import updatePSL

from trackingprotection_tools import DisconnectParser

from constants import (
    ALL_TAGS,
    DEFAULT_DISCONNECT_LIST_CATEGORIES,
    DEFAULT_DISCONNECT_LIST_TAGS,
    DNT_EFF_SECTIONS,
    DNT_SECTIONS,
    DNT_W3C_SECTIONS,
    FASTBLOCK_SECTIONS,
    PLUGIN_SECTIONS,
    PRE_DNT_SECTIONS,
    TEST_DOMAIN_TEMPLATE,
    WHITELIST_SECTIONS,
)
from publish2cloud import (
    publish_to_cloud
)

updatePSL()
psl = PublicSuffixList()

DISCONNECT_MAPPING = os.path.join(
    os.path.dirname(__file__), 'disconnect_mapping.json')
GITHUB_API_URL = 'https://api.github.com/repos/mozilla-services'
SHAVAR_PROD_LISTS_BRANCHES_PATH = '/shavar-prod-lists/branches'


def get_output_and_log_files(config, section):
    output_file = None
    log_file = None
    output_filename = config.get(section, "output")
    if output_filename:
        output_file = open(output_filename, "wb")
        log_file = open(output_filename + ".log", "w")
    return output_file, log_file


def get_list_url(config, section, key):
    """Return the requested list URL (or the default, if it isn't found)"""
    try:
        url = config.get(section, key)
    except ConfigParser.NoOptionError:
        url = config.get("main", "default_disconnect_url")
    return url


def load_json_from_url(config, section, key):
    url = get_list_url(config, section, key)
    try:
        loaded_json = json.loads(urllib2.urlopen(url).read())
    except Exception:
        sys.stderr.write("Error loading %s\n" % url)
        sys.exit(-1)
    return loaded_json


# bring a URL to canonical form as described at
# https://web.archive.org/web/20160422212049/https://developers.google.com/safe-browsing/developers_guide_v2#Canonicalization
def canonicalize(d):
    if (not d or d == ""):
        return d

    # remove tab (0x09), CR (0x0d), LF (0x0a)
    # TODO?: d, _subs_made = re.subn("\t|\r|\n", "", d)
    d = re.subn("\t|\r|\n", "", d)[0]

    # remove any URL fragment
    fragment_index = d.find("#")
    if (fragment_index != -1):
        d = d[0:fragment_index]

    # repeatedly unescape until no more hex encodings
    while (1):
        _d = d
        d = urllib2.unquote(_d)
        # if decoding had no effect, stop
        if (d == _d):
            break

    # extract hostname (scheme://)(username(:password)@)hostname(:port)(/...)
    # extract path
    # TODO?: use urlparse ?
    url_components = re.match(
        re.compile(
            "^(?:[a-z]+\:\/\/)?(?:[a-z]+(?:\:[a-z0-9]+)?@)?([^\/^\?^\:]+)(?:\:[0-9]+)?(\/(.*)|$)"  # noqa
        ), d)
    host = url_components.group(1)
    path = url_components.group(2) or ""
    path = re.subn(r"^(\/)+", "", path)[0]

    # remove leading and trailing dots
    # TODO?: host, _subs_made = re.subn("^\.+|\.+$", "", host)
    host = re.subn(r"^\.+|\.+$", "", host)[0]
    # replace consequtive dots with a single dot
    # TODO?: host, _subs_made = re.subn("\.+", ".", host)
    host = re.subn(r"\.+", ".", host)[0]
    # lowercase the whole thing
    host = host.lower()

    # percent-escape any characters <= ASCII 32, >= 127, or '#' or '%'
    _path = ""
    for i in path:
        if (ord(i) <= 32 or ord(i) >= 127 or i == '#' or i == '%'):
            _path += urllib2.quote(i)
        else:
            _path += i

    # Note: we do NOT append the scheme
    # because safebrowsing lookups ignore it
    return host + "/" + _path


def add_domain_to_list(domain, previous_domains, allow_list, log_file, output):
    """Prepare domain to be added to output list.

    Returns `True` if a domain was added, `False` otherwise"""
    canon_d = canonicalize(domain)
    if (canon_d not in previous_domains) and (domain not in allow_list):
        # check if the domain is in the public suffix list
        # SafeBrowsing keeps trailing '/', PublicSuffix does not
        psl_d = canon_d.rstrip('/')
        if psl.publicsuffix(psl_d) == psl_d:
            if log_file:
                log_file.write("[Public Suffix] %s; Skipping.\n" % psl_d)
            return False
    if log_file:
        log_file.write("[m] %s >> %s\n" % (domain, canon_d))
        log_file.write("[canonicalized] %s\n" % (canon_d))
        log_file.write("[hash] %s\n" % hashlib.sha256(canon_d).hexdigest())
    previous_domains.add(canon_d)
    output.append(hashlib.sha256(canon_d).digest())
    return True


def get_domains_from_category_filters(parser, category_filters):
    if type(category_filters) != list:
        raise ValueError(
            "Parameter `category_filters` must be a list of strings. "
            "You passed %s of type %s" %
            (category_filters, type(category_filters))
        )
    output = parser.get_domains_with_category(category_filters[0])
    print(" * filter %s matched %d domains"
          % (category_filters[0], len(output)))
    for category_filter in category_filters[1:]:
        result = parser.get_domains_with_category(category_filter)
        output.intersection_update(result)
        print(
            " * filter %s matched %d domains. Reduced set to %d items."
            % (category_filter, len(result), len(output))
        )
    return output


def get_domains_from_filters(parser, category_filters,
                             category_exclusion_filters=[],
                             dnt_filter="", tag_filters={}):
    """Apply filters to the Disconnect list to return a set of matching domains

    Parameters
    ----------
    parser : DisconnectParser
        An instance of the parser set to remap the Disconnect category
    category_filters : list of list of strings
        A filter to restrict output to the specified top-level categories.
        Each filter should be a comma-separated list of top-level categories
        to restrict the list to. If more than one filter is provided, the
        intersection of the filters is returned.
        Example:
            `[['Advertising', 'Analytics'], ['Fingerprinting']]` will return
            domains in either the Advertising or Analytics category AND in the
            Fingerprinting category.
    category_exclusion_filters : list of list of strings, optional
        A filter to exclude domains from the specified top-level categories.
        The list format is the same as `category_filters`.
    dnt_filter : string, optional
        A filter to restrict output to section of the list with the
        specified DNT tag.
        NOTE: The `dnt_filter` is used to further filter the list, as well as
        to filter tagged domains out of a list that doesn't specify a tag. Thus
        lists that use the default ("") will not contain any domain that has
        a `dnt` tag.
    tag_filters : set of strings, optional
        A filter to restrict output to sections of the list with the specified
        sub-category tags.

    Returns
    -------
    set : Domains from `parser` that match the given filters
    """
    # Apply category filters
    output = get_domains_from_category_filters(parser, category_filters)

    # Apply exclusion filters
    if len(category_exclusion_filters) > 0:
        before = len(output)
        output.difference_update(
            get_domains_from_category_filters(
                parser, category_exclusion_filters
            )
        )
        print(" * exclusion filters removed %d domains from output"
              % (before - len(output)))

    # Filter by DNT tag
    if dnt_filter == "":
        result = parser.get_domains_with_tag(["w3c", "eff"])
        output = output.difference(result)
        print(" * removing %d rule(s) due to DNT exceptions" % len(result))
    else:
        result = parser.get_domains_with_tag(dnt_filter)
        output = output.intersection(result)
        print(" * found %d rule(s) with DNT filter %s. Filtered output to %d" %
              (len(result), dnt_filter, len(output)))

    # Apply tag filters
    if len(tag_filters) > 0:
        result = parser.get_domains_with_tag(tag_filters)
        output = output.intersection(result)
        print(" * found %d rule(s) with filter %s. Filtered output to %d." %
              (len(result), tag_filters, len(output)))

    return output


def write_safebrowsing_blocklist(domains, output_name, allow_list, log_file,
                                 chunk, output_file, name):
    """Generates safebrowsing-compatible blocklist from a set of `domains`.

    Args:
      domains: a list of hostnames and/or hostname+paths to add to blocklist
      allow_list: Hosts that we can't put on the blocklist.
      chunk: The chunk number to use.
      output_file: A file-handle to the output file.
      log_file: A filehandle to the log file.
      name : The section name from `shavar_list_creation.ini`
      output_name : The output filename from `shavar_list_creation.ini`
    """
    # Number of items published
    publishing = 0

    # Total number of bytes, 0 % 32
    hashdata_bytes = 0

    # Remember previous domains so we don't print them more than once
    previous_domains = set()

    # Array holding hash bytes to be written to f_out. We need the total bytes
    # before writing anything.
    output = []

    # Add a static test domain to list
    added = add_domain_to_list(
        TEST_DOMAIN_TEMPLATE % output_name,
        previous_domains, allow_list, log_file, output
    )
    if added:
        # TODO?: hashdata_bytes += hashdata.digest_size
        hashdata_bytes += 32
        publishing += 1

    for d in domains:
        added = add_domain_to_list(
            d, previous_domains, allow_list, log_file, output
        )
        if added:
            # TODO?: hashdata_bytes += hashdata.digest_size
            hashdata_bytes += 32
            publishing += 1

    # Write safebrowsing-list format header
    output_string = "a:%u:32:%s\n" % (chunk, hashdata_bytes)
    output_string += ''.join(output)
    if output_file:
        output_file.write(output_string)

    if (name in FASTBLOCK_SECTIONS):
        print("Fastblock(%s): publishing %d items; file size %d" % (
            name, publishing, len(output_string)))
    else:
        print("Tracking protection(%s): publishing %d items; file size %d" % (
            name, publishing, len(output_string)))
    return


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
                    log_file.write(
                        "[entity] %s >> (canonicalized) %s, hash %s\n"
                        % (name, d, h.hexdigest())
                    )
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
        print("Fastblock whitelist(%s): publishing %d items; file size %d" % (
            list_variant, publishing, output_size))
    else:
        print("Entity whitelist(%s): publishing %d items; file size %d" % (
            list_variant, publishing, output_size))


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
                log_file.write(
                    "[plugin-blocklist] %s >> (canonicalized) %s, hash %s\n"
                    % (d, canon_d, h.hexdigest())
                )
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
    print("Plugin blocklist(%s): publishing %d items; file size %d" % (
        list_variant, publishing, output_size))


def get_tracker_lists(config, section, chunknum):
    if (section in FASTBLOCK_SECTIONS):
        # process fastblock
        blocklist_url = get_list_url(config, section, "blocklist_url")
    else:
        # process disconnect
        blocklist_url = get_list_url(config, section, "disconnect_url")
    parser = DisconnectParser(
        blocklist_url=blocklist_url,
        disconnect_mapping=DISCONNECT_MAPPING
    )

    # load our allowlist
    allowed = set()
    try:
        allowlist_url = config.get(section, "allowlist_url")
    except Exception:
        allowlist_url = None
    # TODO: refactor into: def get_allowed_domains(allowlist_url)
    if allowlist_url:
        for line in urllib2.urlopen(allowlist_url).readlines():
            line = line.strip()
            # don't add blank lines or comments
            if not line or line.startswith('#'):
                continue
            allowed.add(line)

    # category filter
    if config.has_option(section, "categories"):
        list_categories = config.get(section, "categories").split(',')
    else:
        list_categories = DEFAULT_DISCONNECT_LIST_CATEGORIES
    list_categories = [x.split('|') for x in list_categories]

    # excluded categories filter
    if config.has_option(section, "excluded_categories"):
        excluded_categories = config.get(
            section, "excluded_categories").split(',')
        excluded_categories = [
            x.split('|') for x in excluded_categories]
    else:
        excluded_categories = list()

    # dnt filter
    if section in DNT_EFF_SECTIONS:
        which_dnt = "eff"
    elif section in DNT_W3C_SECTIONS:
        which_dnt = "w3c"
    else:
        which_dnt = ""

    # tag filter
    try:
        desired_tags = set(config.get(
            section, "disconnect_tags").split(','))
        if len(desired_tags.difference(ALL_TAGS)) > 0:
            raise ValueError(
                "The configuration file contains unsupported tags.\n"
                "Supported tags: %s\nConfig file tags: %s" %
                (ALL_TAGS, desired_tags)
            )
    except ConfigParser.NoOptionError:
        desired_tags = DEFAULT_DISCONNECT_LIST_TAGS

    # Retrieve domains that match filters
    print("\n------ %s ------" % section)
    print("-->blocklist: %s)" % blocklist_url)
    blocked_domains = get_domains_from_filters(
        parser, list_categories, excluded_categories,
        which_dnt, desired_tags)

    output_file, log_file = get_output_and_log_files(config, section)
    # Write blocklist in a format compatible with safe browsing
    output_filename = config.get(section, "output")
    write_safebrowsing_blocklist(
        blocked_domains, output_filename, allowed, log_file,
        chunknum, output_file, section
    )
    return output_file, log_file


def edit_config(config, section, option, old_value, new_value):
    current = config.get(section, option)
    edited_config = current.replace(old_value, new_value)
    config.set(section, option, edited_config)
    print('Edited {opt} in {sect} to: {new}'.format(
        opt=option, sect=section, new=config.get(section, option))
    )


def version_configurations(config, section, version, revert=None):
    initial_disconnect_url_val = 'master'
    initial_s3_key_value = 'tracking/'
    if revert:
        if config.has_option(section, 'disconnect_url'):
            edit_config(
                config, section, option='disconnect_url',
                old_value=version, new_value=initial_disconnect_url_val)
        if config.has_option(section, 's3_key'):
            versioned_key = 'tracking/{ver}/'.format(ver=version)
            edit_config(
                config, section, option='s3_key',
                old_value=versioned_key, new_value=initial_s3_key_value)
        return

    if config.has_option(section, 'disconnect_url'):
        edit_config(
            config, section, option='disconnect_url',
            old_value=initial_disconnect_url_val, new_value=version)

    if config.has_option(section, 's3_key'):
        versioned_key = 'tracking/{ver}/'.format(ver=version)
        edit_config(
            config, section, option='s3_key',
            old_value=initial_s3_key_value, new_value=versioned_key)


def revert_config(config, version):
    edit_config(
        config=config, section='main', option='default_disconnect_url',
        old_value=version, new_value='master')
    for section in config.sections():
        versioning_needed = (
            config.has_option(section, 'versioning_needed')
                and config.get(section, 'versioning_needed')
        )
        if not versioning_needed:
            continue
        version_configurations(config, section, version, revert=True)


def get_versioned_lists(config, chunknum, version):
    '''
    Checks `versioning_needed` in each sections then versions the tracker lists
    by overwriting the existing SafeBrowsing formatted files.
    '''
    edit_config(
        config, section='main', option='default_disconnect_url',
        old_value='master', new_value=version)
    for section in config.sections():
        versioning_needed = (
            config.has_option(section, 'versioning_needed')
                and config.get(section, 'versioning_needed')
        )
        if not versioning_needed:
            continue
        print('Version {ver} for {output}'.format(
            ver=version, output=config.get(section, 'output'))
        )
        version_configurations(config, section, version)
        output_file, log_file = get_tracker_lists(
            config, section, chunknum)

    if output_file:
        output_file.close()
    if log_file:
        log_file.close()


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
            output_file, log_file = get_tracker_lists(
                config, section, chunknum)

        if section in PLUGIN_SECTIONS:
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

            output_file, log_file = get_output_and_log_files(config, section)
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

    publish_to_cloud(config, chunknum)

    # create and publish versioned lists
    resp = requests.get(GITHUB_API_URL + SHAVAR_PROD_LISTS_BRANCHES_PATH)
    if resp:
        shavar_prod_lists_branches = resp.json()
        for branch in shavar_prod_lists_branches:
            branch_name = branch.get('name')
            ver = version.parse(branch_name)
            if isinstance(ver, version.Version):
                get_versioned_lists(config, chunknum, version=branch_name)
                print('*** Publish Versioned Lists ***')
                publish_to_cloud(config, chunknum, check_versioning=True)
                print('*** Revert Configs ***')
                revert_config(config, branch_name)
            else:
                print(branch_name + ' is not a versioning branch')
    else:
        print('Unable to get branches from shavar-prod-lists repo')


if __name__ == "__main__":
    main()
