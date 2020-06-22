import hashlib
import time

import pytest
from mock import call, patch, mock_open

import lists2safebrowsing as l2s


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
    ("percent_escape_special_chars_2", "http://\x01\x8a.com/", "%01%8A.com/"),
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

TEST_SECTION = "tracking-protection-test"

PRINT_MSG = "%s(%s): publishing %d items; file size %d\n"


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


def _write_safebrowsing_blocklist(chunknum, version):
    """Auxiliary function for write_safebrowsing_blocklist tests."""
    domain = CANONICALIZE_TESTCASES[0]
    output_name = "test-track-digest256"

    with patch("test_lists2safebrowsing.open", mock_open()):
        with open(output_name, "wb") as output_file:
            # Include the domain twice in the input set to make sure it
            # is only added to the blocklist once
            l2s.write_safebrowsing_blocklist(
                {domain[1], domain[2]}, output_name, None, chunknum,
                output_file, TEST_SECTION, version)

    return output_file.write.call_args_list


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
