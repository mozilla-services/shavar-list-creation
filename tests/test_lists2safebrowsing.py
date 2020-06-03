import pytest

from lists2safebrowsing import canonicalize


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


def test_canonicalize_return_type():
    """Test that the return type of canonicalize is str."""
    assert type(canonicalize("https://host.com/path")) is str


def test_canonicalize_invalid_input():
    """Test that canonicalize raises a ValueError when input is invalid."""
    with pytest.raises(ValueError):
        canonicalize("http://3279880203/blah")
    with pytest.raises(ValueError):
        canonicalize("http://www.google.com/blah/..")
    with pytest.raises(ValueError):
        canonicalize("http://www.google.com/foo/./bar")


@pytest.mark.parametrize("url,expected",
                         [pytest.param(url, expected, id=id)
                             for id, url, expected in CANONICALIZE_TESTCASES])
def test_canonicalize(url, expected):
    """Validate the canonicalization implementation.

    Use the test cases suggested in the Safe Browsing v2 API
    documentation with some adjustments and additions.
    """
    assert canonicalize(url) == expected
