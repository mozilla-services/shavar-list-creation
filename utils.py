#!/usr/bin/env python

import configparser
import hashlib
from trackingprotection_tools import DisconnectParser
import sys
import json
from publicsuffixlist import PublicSuffixList
from publicsuffixlist.update import updatePSL
from urllib.request import urlopen

from constants import (
    ALL_TAGS,
    DEFAULT_DISCONNECT_LIST_CATEGORIES,
    DEFAULT_DISCONNECT_LIST_TAGS,
    DNT_EFF_SECTIONS,
    DNT_W3C_SECTIONS,
)

updatePSL()
psl = PublicSuffixList(only_icann=True)


def get_blocked_domains(config, section):
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
    return blocked_domains


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

def load_json_from_url(config, section, key):
    url = get_list_url(config, section, key)
    try:
        loaded_json = json.loads(urlopen(url).read())
    except Exception as e:
        sys.stderr.write("Error loading %s: %s\n" % (url, repr(e)))
        sys.exit(-1)
    return loaded_json

def get_list_url(config, section, key):
    """Return the requested list URL (or the default, if it isn't found)"""
    try:
        url = config.get(section, key)
    except configparser.NoOptionError:
        url = config.get("main", "default_disconnect_url")
    return url

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