#!/usr/bin/env python

import configparser
import hashlib
import json
import os
import re
import requests
import sys
import time
from urllib.parse import quote, unquote
from urllib.request import urlopen

from packaging import version as p_version
from publicsuffixlist import PublicSuffixList
from publicsuffixlist.update import updatePSL

from trackingprotection_tools import DisconnectParser

from constants import (
    ALL_TAGS,
    DEFAULT_DISCONNECT_LIST_CATEGORIES,
    DEFAULT_DISCONNECT_LIST_TAGS,
    DNT_EFF_SECTIONS,
    DNT_EMAIL_SECTIONS,
    DNT_SECTIONS,
    DNT_W3C_SECTIONS,
    PLUGIN_SECTIONS,
    PRE_DNT_SECTIONS,
    LARGE_ENTITIES_SECTIONS,
    STANDARD_ENTITY_SECTION,
    TEST_DOMAIN_TEMPLATE,
    VERSION_EMAIL_CATEGORY_INTRODUCED,
    VERS_LARGE_ENTITIES_SEPARATION_STARTED,
    ENTITYLIST_SECTIONS,
)
from publish2cloud import (
    publish_to_cloud
)

updatePSL()
psl = PublicSuffixList(only_icann=True)

GITHUB_API_URL = 'https://api.github.com'
SHAVAR_PROD_LISTS_BRANCHES_PATH = (
    '/repos/mozilla-services/shavar-prod-lists/branches?per_page=100'
)


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
    except configparser.NoOptionError:
        url = config.get("main", "default_disconnect_url")
    return url


def load_json_from_url(config, section, key):
    url = get_list_url(config, section, key)
    try:
        loaded_json = json.loads(urlopen(url).read())
    except Exception as e:
        sys.stderr.write("Error loading %s: %s\n" % (url, repr(e)))
        sys.exit(-1)
    return loaded_json


# bring a URL to canonical form as described at
# https://web.archive.org/web/20160422212049/https://developers.google.com/safe-browsing/developers_guide_v2#Canonicalization
def canonicalize(d):
    if (not d or d == ""):
        return d

    # remove tab (0x09), CR (0x0d), LF (0x0a)
    # TODO?: d, _subs_made = re.subn("\t|\r|\n", "", d)
    d = re.sub("\t|\r|\n", "", d)

    # remove any URL fragment
    fragment_index = d.find("#")
    if (fragment_index != -1):
        d = d[0:fragment_index]

    # repeatedly unescape until no more hex encodings
    while (1):
        _d = d
        d = unquote(_d)
        # if decoding had no effect, stop
        if (d == _d):
            break

    # remove leading and trailing whitespace
    d = d.strip()

    # extract hostname (scheme://)(username(:password)@)hostname(:port)(/...)
    # extract path
    # TODO?: use urlparse ?
    url_components = re.match(
        re.compile(
            "^(?:[a-z]+\:\/\/)?(?:[a-z]+(?:\:[a-z0-9]+)?@)?([^\/^\?^\:]+)(?:\:[0-9]+)?(\/(.*)|$)"  # noqa
        ), d)
    host = url_components.group(1)
    path = url_components.group(2) or ""

    # Replace consecutive slashes in the path with a single slash but
    # keep the query parameters intact
    query_params = ""
    query_index = path.find("?")
    if query_index != -1:
        query_params = path[query_index:]
        path = path[:query_index]
    path = re.sub(r"\/\/+", "/", path)
    if re.search(r"\/\.\.?(\/|$)", path):
        raise ValueError("Invalid path: '%s'. Paths should not contain "
                         "'/../' or '/./' sequences" % path)
    path = path + query_params

    # remove leading and trailing dots
    # TODO?: host, _subs_made = re.subn("^\.+|\.+$", "", host)
    host = re.sub(r"^\.+|\.+$", "", host)
    # replace consecutive dots with a single dot
    # TODO?: host, _subs_made = re.subn("\.+", ".", host)
    host = re.sub(r"\.+", ".", host)
    if "." not in host:
        raise ValueError("Invalid hostname: '%s'. Hostnames must "
                         "contain at least one dot" % host)
    # lowercase the whole thing
    host = host.lower()

    # Note: we do NOT append the scheme and the port because
    # safebrowsing lookups ignore them
    url = host + "/" + path[1:]

    # percent-escape any characters <= ASCII 32, >= 127, or '#' or '%'
    _url = ""
    for i in url:
        if (ord(i) <= 32 or ord(i) >= 127 or i == '#' or i == '%'):
            _url += quote(i)
        else:
            _url += i

    return _url


def add_domain_to_list(domain, canonicalized_domain, previous_domain,
                       log_file, output):
    """Prepare domain to be added to output list.

    Returns `True` if a domain was added, `False` otherwise"""
    if canonicalized_domain == previous_domain:
        return False
    # Check if the domain is in the public (ICANN) section of the Public
    # Suffix List. See:
    # https://github.com/mozilla-services/shavar-list-creation/issues/102
    # SafeBrowsing keeps trailing '/', PublicSuffix does not
    psl_d = canonicalized_domain.rstrip('/')
    if psl.publicsuffix(psl_d) == psl_d:
        raise ValueError("Domain '%s' is in the public section of the "
                         "Public Suffix List" % psl_d)
    domain_hash = hashlib.sha256(canonicalized_domain.encode())
    if log_file:
        log_file.write("[m] %s >> %s\n" % (domain, canonicalized_domain))
        log_file.write("[canonicalized] %s\n" % (canonicalized_domain))
        log_file.write("[hash] %s\n" % domain_hash.hexdigest())
    output.append(domain_hash.digest())
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
        An instance of the Disconnect list parser
    category_filters : list of lists of strings
        A filter to restrict output to the specified top-level categories.
        Each filter should be a comma-separated list of top-level categories
        to restrict the list to. If more than one filter is provided, the
        intersection of the filters is returned.
        Example:
            `[['Advertising', 'Analytics'], ['FingerprintingInvasive']]`
            will return domains in either the Advertising or Analytics
            category AND in the FingerprintingInvasive category.
    category_exclusion_filters : list of lists of strings, optional
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


def write_safebrowsing_blocklist(domains, output_name, log_file, chunk,
                                 output_file, name, version):
    """Generates safebrowsing-compatible blocklist from a set of `domains`.

    Args:
      domains: a set of hostnames and/or hostname+paths to add to blocklist
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

    # Remember the previous domain so we don't print it more than once
    previous_domain = None

    # Array holding hash bytes to be written to output_file. We need the
    # total bytes before writing anything
    output = []

    # Add a static test domain to list
    test_domain = TEST_DOMAIN_TEMPLATE % output_name
    canonicalized_domain = canonicalize(test_domain)
    num_test_domain_added = 0
    added = add_domain_to_list(test_domain, canonicalized_domain,
                               previous_domain, log_file, output)
    if added:
        num_test_domain_added += 1
        previous_domain = canonicalized_domain

    if version:
        test_domain = '{0}-{1}'.format(version.replace('.', '-'), test_domain)
        canonicalized_domain = canonicalize(test_domain)
        added = add_domain_to_list(test_domain, canonicalized_domain,
                                   previous_domain, log_file, output)
        if added:
            num_test_domain_added += 1
            previous_domain = canonicalized_domain

    if num_test_domain_added > 0:
        # TODO?: hashdata_bytes += hashdata.digest_size
        hashdata_bytes += (32 * num_test_domain_added)
        publishing += num_test_domain_added

    domains = [(d, canonicalize(d)) for d in domains]
    # Sort the domains before writing their hashes to the safebrowsing
    # list file to ensure that changes in the order of domains will not
    # cause unnecessary updates
    domains.sort(key=lambda d: d[1])
    added_domains = []
    for domain, canonicalized_domain in domains:
        added = add_domain_to_list(domain, canonicalized_domain,
                                   previous_domain, log_file, output)
        if added:
            # TODO?: hashdata_bytes += hashdata.digest_size
            hashdata_bytes += 32
            publishing += 1
            previous_domain = canonicalized_domain
            added_domains.append(domain)

    # Write safebrowsing-list format header
    output_bytes = b"a:%d:32:%d\n" % (chunk, hashdata_bytes)
    output_bytes += b''.join(output)
    # When testing on shavar-prod-lists no output file is provided
    if output_file:
        output_file.write(output_bytes)

    print("Tracking protection(%s): publishing %d items; file size %d" %
          (name, publishing, len(output_bytes)))
    return added_domains


def process_entitylist(incoming, chunk, output_file, log_file, list_variant):
    """
    Expects a dict from a loaded JSON blob.
    """
    publishing = 0
    hashdata_bytes = 0
    output = []

    for name, entity in sorted(incoming.items()):
        urls = set()
        for prop in entity['properties']:
            for res in entity['resources']:
                if prop == res:
                    continue
                urls.add(canonicalize('%s/?resource=%s' % (prop, res)))
        urls = sorted(urls)
        for url in urls:
            h = hashlib.sha256(url.encode())
            if log_file:
                log_file.write(
                    "[entity] %s >> (canonicalized) %s, hash %s\n"
                    % (name, url, h.hexdigest())
                )
            publishing += 1
            hashdata_bytes += 32
            output.append(h.digest())

    # Write the data file
    output_file.write(b"a:%d:32:%d\n" % (chunk, hashdata_bytes))
    for o in output:
        output_file.write(o)

    output_file.flush()
    output_size = os.fstat(output_file.fileno()).st_size
    print("Entity list(%s): publishing %d items; file size %d"
          % (list_variant, publishing, output_size))


def process_plugin_blocklist(incoming, chunk, output_file, log_file,
                             list_variant):
    publishing = 0
    hashdata_bytes = 0
    previous_domain = None
    output = []

    domains = [(d, canonicalize(d)) for d in incoming]
    domains.sort(key=lambda d: d[1])
    for domain, canonicalized_domain in domains:
        if canonicalized_domain != previous_domain:
            h = hashlib.sha256(canonicalized_domain.encode())
            if log_file:
                log_file.write(
                    "[plugin-blocklist] %s >> (canonicalized) %s, hash %s\n"
                    % (domain, canonicalized_domain, h.hexdigest())
                )
            publishing += 1
            hashdata_bytes += 32
            previous_domain = canonicalized_domain
            output.append(h.digest())

    # Write the data file
    output_file.write(b"a:%d:32:%d\n" % (chunk, hashdata_bytes))
    for o in output:
        output_file.write(o)

    output_file.flush()
    output_size = os.fstat(output_file.fileno()).st_size
    print("Plugin blocklist(%s): publishing %d items; file size %d" % (
        list_variant, publishing, output_size))


def get_json_list(config, section, parser, blocked_domains):
    companies = set()
    list_name = config.get(section, 'output')
    if config.has_option(section, 'version'):
        list_name = '{}-{}'.format(config.get(section, 'version'), list_name)
    json_file = open(list_name + '.json', "w")
    json.dump(blocked_domains, json_file, indent=2)
    json_file.close()


def get_tracker_lists(config, section, chunknum):
    blocklist_url = get_list_url(config, section, "disconnect_url")
    parser = DisconnectParser(blocklist_url=blocklist_url)

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
    except configparser.NoOptionError:
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
    version = (config.has_option(section, "version")
               and config.get(section, "version"))
    sorted_domains = write_safebrowsing_blocklist(
        blocked_domains, output_filename, log_file, chunknum,
        output_file, section, version
    )
    get_json_list(
        config, section, parser, sorted_domains)
    return output_file, log_file


def get_entity_lists(config, section, chunknum):
    if config.has_option(section, 'version'):
        version = p_version.parse(config.get(section, 'version'))

    channel_needs_separation = (
        not config.has_option(section, 'version')
        or (version.release[0] >= VERS_LARGE_ENTITIES_SEPARATION_STARTED)
    )

    list_needs_separation = (
        section == STANDARD_ENTITY_SECTION
        or section in LARGE_ENTITIES_SECTIONS
    )
    output_file, log_file = get_output_and_log_files(config, section)

    # download and load the business entity oriented list
    entitylist = load_json_from_url(
        config, section, "entity_url"
    ).pop('entities')

    if channel_needs_separation and list_needs_separation:
        google_entitylist = {}
        google_entitylist['Google'] = entitylist.pop('Google')

    if section in LARGE_ENTITIES_SECTIONS:
        process_entitylist(google_entitylist, chunknum,
                           output_file, log_file, section)
    else:
        process_entitylist(entitylist, chunknum, output_file,
                           log_file, section)
    return output_file, log_file


def get_plugin_lists(config, section, chunknum):
    # load the plugin blocklist
    blocked = set()
    blocklist_url = config.get(section, "blocklist")
    if not blocklist_url:
        raise ValueError("The 'blocklist' key in section '%s' of the "
                         "configuration file is empty. A plugin "
                         "blocklist URL must be specified." % section)

    for line in urlopen(blocklist_url).readlines():
        line = line.decode().strip()
        # don't add blank lines or comments
        if not line or line.startswith('#'):
            continue
        blocked.add(line)

    output_file, log_file = get_output_and_log_files(config, section)
    process_plugin_blocklist(blocked, chunknum, output_file, log_file,
                             section)

    return output_file, log_file


def edit_config(config, section, option, old_value, new_value):
    current = config.get(section, option)
    edited_config = current.replace(old_value, new_value)
    config.set(section, option, edited_config)
    print('Edited {opt} in {sect} to: {new}'.format(
        opt=option, sect=section, new=config.get(section, option))
    )


def version_configurations(config, section, version, revert=False):
    initial_source_url_value = 'master'
    section_has_disconnect_url = (
        section in PRE_DNT_SECTIONS
        or section in DNT_SECTIONS
        or section == 'main'
    )
    if section_has_disconnect_url:
        initial_s3_key_value = 'tracking/'
        source_url = 'disconnect_url'
        versioned_key = 'tracking/{ver}/'.format(ver=version)

    if section in ENTITYLIST_SECTIONS:
        initial_s3_key_value = 'entity/'
        source_url = 'entity_url'
        versioned_key = 'entity/{ver}/'.format(ver=version)

    old_source_url = initial_source_url_value
    new_source_url = version
    old_s3_key = initial_s3_key_value
    new_s3_key = versioned_key
    ver_val = version
    if revert:
        old_source_url = version
        new_source_url = initial_source_url_value
        old_s3_key = versioned_key
        new_s3_key = initial_s3_key_value
        ver_val = ""

    # change the config
    if config.has_option(section, source_url):
        edit_config(
            config, section, option=source_url,
            old_value=old_source_url, new_value=new_source_url)

    if config.has_option(section, 's3_key'):
        edit_config(
            config, section, option='s3_key',
            old_value=old_s3_key, new_value=new_s3_key)

    config.set(section, 'version', ver_val)


def revert_config(config, version):
    edit_config(
        config=config, section='main', option='default_disconnect_url',
        old_value=version, new_value='master')
    for section in config.sections():
        versioning_needed = (
            config.has_option(section, 'versioning_needed')
            and config.getboolean(section, 'versioning_needed')
        )
        if not versioning_needed:
            continue
        version_configurations(config, section, version, revert=True)


def get_versioned_lists(config, chunknum, version):
    """
    Checks `versioning_needed` in each section then versions the tracker lists
    by overwriting the existing SafeBrowsing formatted files.
    """
    edit_config(
        config, section='main', option='default_disconnect_url',
        old_value='master', new_value=version)
    did_versioning = False
    for section in config.sections():
        versioning_needed = (
            config.has_option(section, 'versioning_needed')
            and config.getboolean(section, 'versioning_needed')
        )
        if not versioning_needed:
            continue
        did_versioning = True
        print('\n*** Version {ver} for {output} ***'.format(
            ver=version, output=config.get(section, 'output'))
        )
        version_configurations(config, section, version)
        ver = p_version.parse(version)
        if (section in PRE_DNT_SECTIONS or section in DNT_SECTIONS):
            skip_section = (
                section in DNT_EMAIL_SECTIONS
                and ver.release[0] < VERSION_EMAIL_CATEGORY_INTRODUCED
            )
            if skip_section:
                # import ipdb; ipdb.set_trace()
                continue
            output_file, log_file = get_tracker_lists(
                config, section, chunknum)

        if section in ENTITYLIST_SECTIONS:
            skip_large_entity_separation = (
                ver.release[0] < VERS_LARGE_ENTITIES_SEPARATION_STARTED
                and section in LARGE_ENTITIES_SECTIONS
            )
            if skip_large_entity_separation:
                continue
            output_file, log_file = get_entity_lists(config, section, chunknum)

    if did_versioning and output_file:
        output_file.close()
    if did_versioning and log_file:
        log_file.close()


def start_versioning(config, chunknum, shavar_prod_lists_branches):
    for branch in shavar_prod_lists_branches:
        branch_name = branch.get('name')
        ver = p_version.parse(branch_name)
        if isinstance(ver, p_version.Version):
            print('\n\n*** Start Versioning for {ver} ***'.format(
                ver=branch_name)
            )
            get_versioned_lists(config, chunknum, version=branch_name)
            print('\n*** Publish Versioned Lists ***')
            # publish_to_cloud(config, chunknum, check_versioning=True)
            print('\n*** Revert Configs ***')
            revert_config(config, branch_name)
        else:
            print('\n\n*** {branch} is not a versioning branch ***'.format(
                branch=branch_name)
            )


def main():
    config = configparser.ConfigParser()
    filename = config.read(["shavar_list_creat_latest_prod.ini"])
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
            output_file, log_file = get_plugin_lists(config, section, chunknum)

        if section in ENTITYLIST_SECTIONS:
            output_file, log_file = get_entity_lists(config, section, chunknum)

    if output_file:
        output_file.close()
    if log_file:
        log_file.close()

    # publish_to_cloud(config, chunknum)

    # create and publish versioned lists
    resp = requests.get(GITHUB_API_URL + SHAVAR_PROD_LISTS_BRANCHES_PATH)
    if resp:
        shavar_prod_lists_branches = resp.json()
        start_versioning(config, chunknum, shavar_prod_lists_branches)
    else:
        print('\n\n*** Unable to get branches from shavar-prod-lists repo ***')


if __name__ == "__main__":
    main()
