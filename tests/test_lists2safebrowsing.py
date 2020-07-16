import ConfigParser
import hashlib
import json
import time

import pytest
from mock import call, patch, mock_open

import lists2safebrowsing as l2s
from constants import (
    LIST_TYPE_ENTITY,
    LIST_TYPE_PLUGIN,
    STANDARD_ENTITY_SECTION,
)


CANONICALIZE_TESTCASES = (
    ("dummy_tracking_domain", "https://base-fingerprinting-track-digest256."
        "dummytracker.org/tracker.js", "base-fingerprinting-track-digest256."
        "dummytracker.org/tracker.js"),
    ("no_change_1", "www.google.com/", "www.google.com/"),
    ("no_change_2", "evil.com/foo;", "evil.com/foo;"),
    ("remove_scheme", "http://www.google.com/", "www.google.com/"),
    ("remove_port", "http://www.gotaport.com:1234/", "www.gotaport.com/"),
    ("add_trailing_slash_1", "www.google.com", "www.google.com/"),
    ("add_trailing_slash_2", "http://notrailingslash.com",
        "notrailingslash.com/"),
    ("remove_surrounding_whitespace_1", "  http://www.google.com/  ",
        "www.google.com/"),
    ("remove_surrounding_whitespace_2", "%20%20http://www.google.com%20%20",
        "www.google.com/"),
    ("handle_hostname_spaces_1", "http:// leadingspace.com/",
        "%20leadingspace.com/"),
    ("handle_hostname_spaces_2", "http://%20leadingspace.com/",
        "%20leadingspace.com/"),
    # FIXME: Enable this test case when we update canonicalize to use urlparse
    # ("handle_hostname_spaces_3", "%20leadingspace.com/",
    #    "%20leadingspace.com/"),
    ("remove_tab_cr_lf", "http://www.google.com/foo\tbar\rbaz\n2",
        "www.google.com/foobarbaz2"),
    ("remove_fragment", "http://www.evil.com/blah#frag", "www.evil.com/blah"),
    ("remove_multiple_fragments", "http://evil.com/foo#bar#baz",
        "evil.com/foo"),
    ("unescape_url_1", "http://host.com/%25%32%35", "host.com/%25"),
    ("unescape_url_2", "http://host.com/%25%32%35%25%32%35",
        "host.com/%25%25"),
    ("unescape_url_3", "http://host.com/%2525252525252525", "host.com/%25"),
    ("unescape_url_4", "http://host.com/asdf%25%32%35asd",
        "host.com/asdf%25asd"),
    ("unescape_url_5", "http://host.com/%%%25%32%35asd%%",
        "host.com/%25%25%25asd%25%25"),
    ("unescape_url_6", "http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73"
        "%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/",
        "168.188.99.26/.secure/www.ebay.com/"),
    ("unescape_url_7", "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBay"
        "secure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/",
        "195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdata"
        "xplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/"),
    ("unescape_url_8", "http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%"
        "255E00%252611%252A22%252833%252944_55%252B", "host%23.com/~a!b@c%23d$"
        "e%25f^00&11*22(33)44_55+"),
    ("remove_leading_dots_from_hostname", "http://...www.google.com/",
        "www.google.com/"),
    ("remove_trailing_dots_from_hostname", "http://www.google.com.../",
        "www.google.com/"),
    ("replace_consecutive_dots_with_one", "http://www.google...com/",
        "www.google.com/"),
    ("lowercase", "http://www.GOOgle.com/", "www.google.com/"),
    ("replace_consecutive_slashes_with_one",
        "http://host.com//twoslashes///more_slashes?even_more//slashes",
        "host.com/twoslashes/more_slashes?even_more//slashes"),
    ("query_parameters_1", "http://www.google.com/q?", "www.google.com/q?"),
    ("query_parameters_2", "http://www.google.com/q?r?",
        "www.google.com/q?r?"),
    ("query_parameters_3", "http://www.google.com/q?r?s",
        "www.google.com/q?r?s"),
    ("query_parameters_4", "http://evil.com/foo?bar;", "evil.com/foo?bar;"),
    ("query_parameters_5", "http://www.google.com/q?r//s/..",
        "www.google.com/q?r//s/.."),
    ("percent_escape_special_chars_1", "http://host.com/ab%23cd",
        "host.com/ab%23cd"),
    ("percent_escape_special_chars_2", "http://\x01\x7f.com/", "%01%7F.com/"),
)

TEST_DOMAIN_HASH = (b"q\xd8Q\xbe\x8b#\xad\xd9\xde\xdf\xa7B\x12\xf0D\xa2"
                    "\xf2\x1d\xcfx\xeaHi\x7f8%\xb5\x99\x83\xc1\x111")
VERSIONED_TEST_DOMAIN_HASH = (b"C]~\x9e\xfeLL\xba\xf5\x17k!5\xe4t\xc4\xcc"
                              "\xd2g\x84\x9cJ\xcb\x83;\xf4\x9f`jjYg")
DUMMYTRACKER_DOMAIN_HASH = (b"\xe5\xa9\x07\xc8\xff6r\xa9\xcb\xc8\xf1\xd3"
                            "\xa2\x11\x0c\\\xbe\x7f\xdb1\xbb^\xdfD\xbcX"
                            "\xa8\xf1U;#\xe2")

WRITE_SAFEBROWSING_BLOCKLIST_TESTCASES = (
    ("version", "78.0",
        (3, 115, b"a:%d:32:96\n", (TEST_DOMAIN_HASH
                                   + VERSIONED_TEST_DOMAIN_HASH
                                   + DUMMYTRACKER_DOMAIN_HASH))),
    ("no_version", None,
        (2, 83, b"a:%d:32:64\n", (TEST_DOMAIN_HASH
                                  + DUMMYTRACKER_DOMAIN_HASH))),
    ("no_test_domains", "78.0",
        (1, 51, b"a:%d:32:32\n", DUMMYTRACKER_DOMAIN_HASH)),
)

TEST_ENTITY_DICT = {
    "license": "",
    "entities": {
      "Google": {
        "properties": ["blogspot.com", "youtube.com"],
        "resources": ["gmail.com", "google-analytics.com"]
      },
      "Twitter": {
        "properties": ["twitter.com"],
        "resources": ["twimg.com", "twitter.com"]
      },
    }
}

PROCESS_ENTITYLIST_EXPECTED_OUTPUT_WRITES = (
    b"a:%d:32:160\n",
    (
        (b"\xa0\xbc\xee\xcaR\x0f\xd6\"\x8e\xf6\x7f\xb1Y\x8dM\xa1#\xdd"
         "\x0b\x18\nn\xb1\x1d\x02SW\x89\xfc;\xc5\xb3"),
        (b"}UA\xa3\x89e\xe6\xa0v\x1fA\xa6[\xd5+\xc3\xd9\xfe\x1d\x83\x90"
         "\x161*\xa1f\x1e\x9ee\x9cV:"),
        (b"\xd9`\xdd\xfe\x97\x96\xa3\xfdJ\xa89\x18\xa2Mgd}\x7f\xf2\xd1z"
         "\x11\x13\xde(m}V{\xdb \xb2"),
        (b"\xf3\xfa\xe4\x8a}\xd8\x8a\xae\xf3\xa0B\xe9\xc8q\xe5\xe1xL"
         "\xc3,\x07\x95\x0f;}nK7\x03u\xea\x0e"),
        (b"\xa8\xe9\xe3EoF\xdb\xe4\x95Q\xc7\xda8`\xf6C\x93\xd8\xf9"
         "\xd9oB\xb5\xae\x86\x92w\"Fuw\xdf"),
    ),
)

PROCESS_ENTITYLIST_EXPECTED_LOG_WRITE_INFO = (
    ("Google", "blogspot.com/?resource=gmail.com",
        "a0bceeca520fd6228ef67fb1598d4da123dd0b180a6eb11d02535789fc3bc5b3"),
    ("Google", "blogspot.com/?resource=google-analytics.com",
        "7d5541a38965e6a0761f41a65bd52bc3d9fe1d839016312aa1661e9e659c563a"),
    ("Google", "youtube.com/?resource=gmail.com",
        "d960ddfe9796a3fd4aa83918a24d67647d7ff2d17a1113de286d7d567bdb20b2"),
    ("Google", "youtube.com/?resource=google-analytics.com",
        "f3fae48a7dd88aaef3a042e9c871e5e1784cc32c07950f3b7d6e4b370375ea0e"),
    ("Twitter", "twitter.com/?resource=twimg.com",
        "a8e9e3456f46dbe49551c7da3860f64393d8f9d96f42b5ae86927722467577df"),
)

PROCESS_PLUGIN_BLOCKLIST_EXPECTED_OUTPUT_WRITES = (
    b"a:%d:32:64\n",
    (
        DUMMYTRACKER_DOMAIN_HASH,
        (b"\xbc\x9a\x8f+o\xff\xd5\x85q\xe1\x88\xbb\x11\x05E\xf8\xfb:"
         "\xf5\x1c\xdf\x1acimPZ\x98p\xa8[\xe5"),
    ),
)

PROCESS_PLUGIN_BLOCKLIST_EXPECTED_LOG_WRITE_INFO = (
    (CANONICALIZE_TESTCASES[0][1], CANONICALIZE_TESTCASES[0][2],
        "e5a907c8ff3672a9cbc8f1d3a2110c5cbe7fdb31bb5edf44bc58a8f1553b23e2"),
    (CANONICALIZE_TESTCASES[1][1], CANONICALIZE_TESTCASES[1][2],
        "bc9a8f2b6fffd58571e188bb110545f8fb3af51cdf1a63696d505a9870a85be5"),
)

GET_ENTITY_LISTS_TESTCASES = (
    ("separation_standard", STANDARD_ENTITY_SECTION, None),
    ("separation_google", "google-whitelist", None),
    ("no_separation", STANDARD_ENTITY_SECTION, "72.0"),
)

ENTITY_LIST_URL = ("https://raw.githubusercontent.com/mozilla-services/"
                   "shavar-prod-lists/master/disconnect-entitylist.json")

TEST_SECTION = "tracking-protection-test"

PRINT_MSG = "%s(%s): publishing %d items; file size %d\n"
LOG_MSG = "[{}] {} >> (canonicalized) {}, hash {}\n"


@pytest.fixture
def chunknum():
    return int(time.time())


def test_canonicalize_return_type():
    """Test that the return type of canonicalize is str."""
    assert type(l2s.canonicalize("https://host.com/path")) is str


def test_canonicalize_invalid_input():
    """Test that canonicalize raises a ValueError when input is invalid."""
    with pytest.raises(ValueError):
        l2s.canonicalize("http://3279880203/blah")
    with pytest.raises(ValueError):
        l2s.canonicalize("http://www.google.com/blah/..")
    with pytest.raises(ValueError):
        l2s.canonicalize("http://www.google.com/foo/./bar")


@pytest.mark.parametrize("url,expected",
                         [pytest.param(url, expected, id=id)
                             for id, url, expected in CANONICALIZE_TESTCASES])
def test_canonicalize(url, expected):
    """Validate the canonicalization implementation.

    Use the test cases suggested in the Safe Browsing v2 API
    documentation with some adjustments and additions.
    """
    assert l2s.canonicalize(url) == expected


def _add_domain_to_list(domain, previous_domains, output):
    """Auxiliary function for add_domain_to_list tests."""
    canonicalized_domain = l2s.canonicalize(domain)
    domain_hash = hashlib.sha256(canonicalized_domain.encode("utf-8"))

    with patch("test_lists2safebrowsing.open", mock_open()):
        with open("test_blocklist.log", "w") as log_file:
            added = l2s.add_domain_to_list(domain, previous_domains,
                                           log_file, output)
            log_writes = log_file.write.call_args_list

    return (added, canonicalized_domain, domain_hash, previous_domains,
            log_writes, output)


def test_add_domain_to_list():
    """Test adding a domain to a blocklist."""
    domain = "https://www.host.com"
    (added, canonicalized_domain, domain_hash, previous_domains,
     log_writes, output) = _add_domain_to_list(domain, set(), [])

    expected_log_writes = [
        call("[m] %s >> %s\n" % (domain, canonicalized_domain)),
        call("[canonicalized] %s\n" % canonicalized_domain),
        call("[hash] %s\n" % domain_hash.hexdigest()),
    ]

    assert added
    assert canonicalized_domain in previous_domains
    assert domain_hash.digest() in output
    assert log_writes == expected_log_writes


def test_add_domain_to_list_psl_public():
    """Test handling of ICANN public suffix list domains.

    add_domain_to_list raises a ValueError
    """
    with pytest.raises(ValueError):
        _add_domain_to_list("https://co.uk", set(), [])


def test_add_domain_to_list_psl_private():
    """Test handling of private public suffix list domains.

    add_domain_to_list adds them to the blocklist
    """
    assert _add_domain_to_list("https://apps.fbsbx.com", set(), [])[0]


def test_add_domain_to_list_duplicate():
    """Test that add_domain_to_list does not add domains twice."""
    domain = "https://duplicate.com"
    (added, canonicalized_domain, domain_hash, previous_domains, _,
     output) = _add_domain_to_list(domain, set(), [])

    assert added
    assert canonicalized_domain in previous_domains
    assert domain_hash.digest() in output

    added, _, _, _, log_writes, output = _add_domain_to_list(
        domain, previous_domains, output)

    assert not added
    assert output == [domain_hash.digest()]
    assert not log_writes


def _write_safebrowsing_blocklist(chunknum, version, write_to_file=True):
    """Auxiliary function for write_safebrowsing_blocklist tests."""
    domain = CANONICALIZE_TESTCASES[0]
    output_name = "test-track-digest256"

    with patch("test_lists2safebrowsing.open", mock_open()):
        with open(output_name, "wb") as output_file:
            output_file = output_file if write_to_file else None
            # Include the domain twice in the input set to make sure it
            # is only added to the blocklist once
            l2s.write_safebrowsing_blocklist(
                {domain[1], domain[2]}, output_name, None, chunknum,
                output_file, TEST_SECTION, version)

    return output_file.write.call_args_list if write_to_file else []


@pytest.mark.parametrize(
    "testcase,version,expected_results",
    [pytest.param(id, version, expected_results, id=id)
        for id, version, expected_results
        in WRITE_SAFEBROWSING_BLOCKLIST_TESTCASES]
)
def test_write_safebrowsing_blocklist(capsys, chunknum, testcase,
                                      version, expected_results):
    """Validate Safe Browsing v2 blocklist generation."""
    if testcase == "no_test_domains":
        # Store reference to original function before mocking it
        original_add_domain_to_list = l2s.add_domain_to_list

        # Only mock the first two calls, which add the test domains
        def side_effect(*args, **kwargs):
            side_effect.call_counter += 1
            if side_effect.call_counter < 3:
                return False
            return original_add_domain_to_list(*args, **kwargs)

        side_effect.call_counter = 0

        with patch("lists2safebrowsing.add_domain_to_list") as m:
            m.side_effect = side_effect
            output_writes = _write_safebrowsing_blocklist(chunknum, version)
    else:
        output_writes = _write_safebrowsing_blocklist(chunknum, version)

    domains_number, file_size, header, hashes = expected_results

    expected_output = header % chunknum + hashes
    expected_print = PRINT_MSG % ("Tracking protection", TEST_SECTION,
                                  domains_number, file_size)

    assert output_writes == [call(expected_output)]
    assert capsys.readouterr().out == expected_print


def test_write_safebrowsing_blocklist_no_output_file(capsys, chunknum):
    """Test write_safebrowsing_blocklist without an output file."""
    _write_safebrowsing_blocklist(chunknum, "78.0", False)

    expected_print = PRINT_MSG % ("Tracking protection", TEST_SECTION,
                                  3, 115)

    assert capsys.readouterr().out == expected_print


@pytest.mark.parametrize("log", [True, False], ids=["log", "no_log"])
@pytest.mark.parametrize("list_type", [LIST_TYPE_ENTITY, LIST_TYPE_PLUGIN])
def test_process_list(capsys, chunknum, log, list_type):
    """Validate entity/plugin list generation."""
    if list_type == LIST_TYPE_ENTITY:
        incoming = TEST_ENTITY_DICT["entities"]
        function = l2s.process_entitylist
        header, hashes = PROCESS_ENTITYLIST_EXPECTED_OUTPUT_WRITES
        log_info = PROCESS_ENTITYLIST_EXPECTED_LOG_WRITE_INFO
        log_id = "entity"
        print_id = "Entity list"
        domains_number = 5
    else:
        incoming = [d[1] for d in CANONICALIZE_TESTCASES[:2]]
        function = l2s.process_plugin_blocklist
        header, hashes = PROCESS_PLUGIN_BLOCKLIST_EXPECTED_OUTPUT_WRITES
        log_info = PROCESS_PLUGIN_BLOCKLIST_EXPECTED_LOG_WRITE_INFO
        log_id = "plugin-blocklist"
        print_id = "Plugin blocklist"
        domains_number = 2

    with patch("test_lists2safebrowsing.open", mock_open()):
        with open("test-list.log", "w") as log_file:
            with patch("test_lists2safebrowsing.open", mock_open()):
                with open("test-list-digest256", "wb") as output_file:
                    log_file = log_file if log else None
                    function(incoming, chunknum, output_file, log_file,
                             TEST_SECTION)

    log_writes = log_file.write.call_args_list if log else []
    output_writes = output_file.write.call_args_list

    expected_output_writes = ([call(header % chunknum)]
                              + [call(h) for h in hashes])

    expected_log_writes = [call(LOG_MSG.format(log_id, *i))
                           for i in log_info] if log else []

    # FIXME: os.fstat returns 0 size for the mocked file
    expected_print = PRINT_MSG % (print_id, TEST_SECTION, domains_number, 0)

    assert output_writes == expected_output_writes
    assert log_writes == expected_log_writes
    assert capsys.readouterr().out == expected_print


@pytest.mark.parametrize(
    "section,version,testcase",
    [pytest.param(section, version, id, id=id)
        for id, section, version in GET_ENTITY_LISTS_TESTCASES]
)
def test_get_entity_lists(chunknum, section, version, testcase):
    """Validate creating an entity list from a configuration section."""
    config = ConfigParser.ConfigParser()
    config.readfp(open("sample_shavar_list_creation.ini"))

    if version:
        config.set(section, "version", version)

    data = json.dumps(TEST_ENTITY_DICT)
    with patch("lists2safebrowsing.urllib2.urlopen",
               mock_open(read_data=data)) as mocked_urlopen, \
            patch("lists2safebrowsing.open", mock_open()) as mocked_open:
        output_file, _ = l2s.get_entity_lists(config, section, chunknum)

    urlopen_calls = mocked_urlopen.call_args_list
    expected_urlopen_calls = [call(ENTITY_LIST_URL)]
    open_calls = mocked_open.call_args_list
    output_filename = config.get(section, "output")
    expected_open_calls = [call(output_filename, "wb"),
                           call(output_filename + ".log", "w")]

    expected_hashes = PROCESS_ENTITYLIST_EXPECTED_OUTPUT_WRITES[1]
    if testcase == "separation_standard":
        expected_hashes = expected_hashes[4:]
    elif testcase == "separation_google":
        expected_hashes = expected_hashes[:4]

    domains_number = len(expected_hashes)

    expected_output_writes = (
        [call(b"a:%d:32:%d\n" % (chunknum, domains_number * 32))]
        + [call(h) for h in expected_hashes]
    )

    # Exclude log writes
    output_writes = output_file.write.call_args_list[domains_number:]

    assert urlopen_calls == expected_urlopen_calls
    assert open_calls == expected_open_calls
    assert output_writes == expected_output_writes
