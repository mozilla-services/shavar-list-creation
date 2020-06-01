import pytest

from lists2safebrowsing import canonicalize


CANONICALIZE_TESTCASES = (
    ("no_change_1", "www.google.com/", "www.google.com/"),
    ("no_change_2", "evil.com/foo;", "evil.com/foo;"),
    ("remove_scheme_1", "http://www.google.com/", "www.google.com/"),
    ("remove_scheme_2", "https://www.securesite.com/", "www.securesite.com/"),
    ("remove_port", "http://www.gotaport.com:1234/", "www.gotaport.com/"),
    ("add_trailing_slash_1", "www.google.com", "www.google.com/"),
    ("add_trailing_slash_2", "http://notrailingslash.com",
        "notrailingslash.com/"),
    ("remove_surrounding_whitespace_1", "  http://www.google.com/  ",
        "www.google.com/"),
    ("remove_surrounding_whitespace_2", "%20%20http://www.google.com%20%20",
        "www.google.com/"),
    ("remove_tab_cr_lf", "http://www.google.com/foo\tbar\rbaz\n2",
        "www.google.com/foobarbaz2"),
    ("remove_fragment", "http://www.evil.com/blah#frag", "www.evil.com/blah"),
    ("remove_multiple_fragments", "http://evil.com/foo#bar#baz",
        "evil.com/foo"),
    ("unescape_url_1", "http://host/%25%32%35", "host/%25"),
    ("unescape_url_2", "http://host/%25%32%35%25%32%35", "host/%25%25"),
    ("unescape_url_3", "http://host/%2525252525252525", "host/%25"),
    ("unescape_url_4", "http://host/asdf%25%32%35asd", "host/asdf%25asd"),
    ("unescape_url_5", "http://host/%%%25%32%35asd%%",
        "host/%25%25%25asd%25%25"),
    ("unescape_url_6", "http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73"
        "%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/",
        "168.188.99.26/.secure/www.ebay.com/"),
    ("unescape_url_7", "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBay"
        "secure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/",
        "195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdata"
        "xplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/"),
    ("remove_leading_dots_from_hostname", "http://...www.google.com/",
        "www.google.com/"),
    ("remove_trailing_dots_from_hostname", "http://www.google.com.../",
        "www.google.com/"),
    ("replace_consecutive_dots_with_one", "http://www.google...com/",
        "www.google.com/"),
    ("lowercase", "http://www.GOOgle.com/", "www.google.com/"),
    ("replace_consecutive_slashes_with_one",
        "http://host.com//twoslashes?more//slashes",
        "host.com/twoslashes?more//slashes"),
    ("query_parameters_1", "http://www.google.com/q?", "www.google.com/q?"),
    ("query_parameters_2", "http://www.google.com/q?r?",
        "www.google.com/q?r?"),
    ("query_parameters_3", "http://www.google.com/q?r?s",
        "www.google.com/q?r?s"),
    ("query_parameters_4", "http://evil.com/foo?bar;", "evil.com/foo?bar;"),
    ("query_parameters_5", "http://www.google.com/q?r//s/..",
        "www.google.com/q?r//s/.."),
    ("percent_escape_hash", "http://host.com/ab%23cd", "host.com/ab%23cd"),
)


def test_canonicalize_return_type():
    """Test that the return type of canonicalize is str."""
    assert type(canonicalize("https://host/path")) is str


@pytest.mark.parametrize("url,expected",
                         [pytest.param(url, expected, id=id)
                             for id, url, expected in CANONICALIZE_TESTCASES])
def test_canonicalize(url, expected):
    """Validate the canonicalization implementation.

    Use the test cases suggested in the Safe Browsing v2 API
    documentation with some adjustments and additions.
    """
    assert canonicalize(url) == expected
