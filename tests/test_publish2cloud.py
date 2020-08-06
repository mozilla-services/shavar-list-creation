import ConfigParser
import os

import boto.s3.connection
import boto.s3.key
import pytest
from mock import mock_open, patch
from moto import mock_s3_deprecated as mock_s3

from publish2cloud import (
    chunk_metadata,
    new_data_to_publish_to_s3,
    publish_to_s3
)


TEST_CHUNKNUM = "0123456789"
TEST_LIST = (b"a:%s:32:32\n" % TEST_CHUNKNUM
             # Hash of test-track-digest256.dummytracker.org/
             + b"q\xd8Q\xbe\x8b#\xad\xd9\xde\xdf\xa7B\x12\xf0D\xa2\xf2"
             "\x1d\xcfx\xeaHi\x7f8%\xb5\x99\x83\xc1\x111")

TEST_LIST_CHECKSUM = ("043493ecb63c5f143a372a5118d04a44df188f238d2b18e6"
                      "cd848ae413a01090")

TEST_CONFIG_SECTION = "test-tracking-protection"
TEST_OUTPUT_FILENAME = "test-tracking-protection-digest256"

TEST_S3_KEY = "test-key"
TEST_S3_BUCKET = "test-bucket"


# Use fixtures to set up a mocked s3 connection and fake AWS credentials
# as suggested on https://github.com/spulec/moto#example-on-usage
@pytest.fixture
def aws_credentials():
    """Mocked AWS credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"


@pytest.fixture
def s3(aws_credentials):
    with mock_s3():
        yield boto.s3.connection.S3Connection()


@pytest.fixture
def config():
    config = ConfigParser.ConfigParser()
    config.add_section("main")
    config.add_section(TEST_CONFIG_SECTION)
    config.set("main", "s3_bucket", TEST_S3_BUCKET)
    config.set(TEST_CONFIG_SECTION, "s3_key", TEST_S3_KEY)
    config.set(TEST_CONFIG_SECTION, "output", TEST_OUTPUT_FILENAME)
    return config


def test_chunk_metadata():
    """Test getting metadata from the chunk header of a list file."""
    with patch("test_publish2cloud.open", mock_open(read_data=TEST_LIST)):
        with open("base-fingerprinting-track-digest256", "rb") as fp:
            metadata = chunk_metadata(fp)

    assert metadata["type"] == "a"
    assert metadata["num"] == TEST_CHUNKNUM
    assert metadata["hash_size"] == "32"
    assert metadata["len"] == "32"
    assert metadata["checksum"] == TEST_LIST_CHECKSUM


def _populate_s3(s3, test_list=None, s3_key=TEST_S3_KEY):
    """Add a bucket and store the given list under a key."""
    bucket = s3.create_bucket(TEST_S3_BUCKET)
    if test_list is not None:
        key = boto.s3.key.Key(bucket)
        key.key = s3_key
        key.set_contents_from_string(test_list)


def test_new_data_to_publish_to_s3_false(s3, config):
    """Test new_data_to_publish_to_s3 when there is no new data."""
    _populate_s3(s3, TEST_LIST)

    assert not new_data_to_publish_to_s3(config, TEST_CONFIG_SECTION,
                                         {"checksum": TEST_LIST_CHECKSUM})


def test_new_data_to_publish_to_s3_true(s3, config):
    """Test new_data_to_publish_to_s3 when there is new data."""
    _populate_s3(s3, TEST_LIST + (32 * b"1"))

    assert new_data_to_publish_to_s3(config, TEST_CONFIG_SECTION,
                                     {"checksum": TEST_LIST_CHECKSUM})


def test_new_data_to_publish_to_s3_new_list(s3, config, capsys):
    """Test new_data_to_publish_to_s3 when the list is not in S3."""
    _populate_s3(s3)

    expected_print = ("%s looks like it hasn't been uploaded to "
                      "s3://%s/%s\n" % (TEST_CONFIG_SECTION,
                                        TEST_S3_BUCKET, TEST_S3_KEY))

    assert new_data_to_publish_to_s3(config, TEST_CONFIG_SECTION,
                                     {"checksum": TEST_LIST_CHECKSUM})
    assert capsys.readouterr().out == expected_print


def test_new_data_to_publish_to_s3_output_as_key(s3, config):
    """Test that `output` is used as the S3 key when there is no `s3_key`."""
    config.remove_option(TEST_CONFIG_SECTION, "s3_key")

    _populate_s3(s3, TEST_LIST, TEST_OUTPUT_FILENAME)

    assert not new_data_to_publish_to_s3(config, TEST_CONFIG_SECTION,
                                         {"checksum": TEST_LIST_CHECKSUM})


def test_new_data_to_publish_to_s3_empty_s3_key(s3, config):
    """Test that new_data_to_publish_to_s3 raises error on empty `s3_key`."""
    config.set(TEST_CONFIG_SECTION, "s3_key", "")

    _populate_s3(s3)

    with pytest.raises(ValueError):
        new_data_to_publish_to_s3(config, TEST_CONFIG_SECTION,
                                  {"checksum": TEST_LIST_CHECKSUM})


def test_new_data_to_publish_to_s3_permissions(s3, config):
    """Test that the expected S3 key permissions are set."""
    _populate_s3(s3, TEST_LIST)

    with patch("publish2cloud.CLOUDFRONT_USER_ID", "test-user-id"):
        assert not new_data_to_publish_to_s3(
            config, TEST_CONFIG_SECTION, {"checksum": TEST_LIST_CHECKSUM}
        )

    # FIXME
    pytest.xfail("key.add_user_grant() does not work with moto")
    key = s3.get_bucket(TEST_S3_BUCKET).get_key(TEST_S3_KEY)
    grants = key.get_acl().acl.grants

    assert len(grants) == 2
    assert grants[0].permission == "FULL_CONTROL"
    assert grants[1].permission == "READ"
    assert grants[1].id == "test-user-id"


def _publish_to_s3(config):
    """Auxiliary function for publish_to_s3 tests."""
    def mock_set_contents_from_filename(self, filename, *args, **kwargs):
        assert filename == TEST_OUTPUT_FILENAME
        boto.s3.key.Key.set_contents_from_string(self, TEST_LIST,
                                                 *args, **kwargs)

    with patch("publish2cloud.boto.s3.key.Key.set_contents_from_filename",
               new=mock_set_contents_from_filename):
        publish_to_s3(config, TEST_CONFIG_SECTION, TEST_CHUNKNUM)


def test_publish_to_s3(s3, config, capsys):
    """Test publishing a list to S3."""
    bucket = s3.create_bucket(TEST_S3_BUCKET)

    _publish_to_s3(config)

    for name in (TEST_S3_KEY, TEST_OUTPUT_FILENAME + "/" + TEST_CHUNKNUM):
        assert bucket.get_key(name).get_contents_as_string() == TEST_LIST
    assert sum(1 for _ in bucket.list()) == 2
    assert capsys.readouterr().out == ("Uploaded to s3: %s\n"
                                       % TEST_CONFIG_SECTION)


def test_publish_to_s3_section_bucket(s3, config, capsys):
    """Test publish_to_s3 with a section-specific bucket."""
    section_bucket = "other-bucket"
    config.set(TEST_CONFIG_SECTION, "s3_bucket", section_bucket)
    bucket = s3.create_bucket(section_bucket)

    _publish_to_s3(config)

    for name in (TEST_S3_KEY, TEST_OUTPUT_FILENAME + "/" + TEST_CHUNKNUM):
        assert bucket.get_key(name).get_contents_as_string() == TEST_LIST
    assert sum(1 for _ in bucket.list()) == 2
    assert capsys.readouterr().out == ("Uploaded to s3: %s\n"
                                       % TEST_CONFIG_SECTION)


def test_publish_to_s3_output_as_key(s3, config, capsys):
    """Test publish_to_s3 when when there is no `s3_key`."""
    config.remove_option(TEST_CONFIG_SECTION, "s3_key")
    bucket = s3.create_bucket(TEST_S3_BUCKET)

    _publish_to_s3(config)

    for name in (TEST_OUTPUT_FILENAME,
                 TEST_OUTPUT_FILENAME + "/" + TEST_CHUNKNUM):
        assert bucket.get_key(name).get_contents_as_string() == TEST_LIST
    assert sum(1 for _ in bucket.list()) == 2
    assert capsys.readouterr().out == ("Uploaded to s3: %s\n"
                                       % TEST_CONFIG_SECTION)


def test_publish_to_s3_versioning(s3, config, capsys):
    """Test publish_to_s3 with list versioning."""
    version = "78.0"
    config.set(TEST_CONFIG_SECTION, "versioning_needed", "true")
    config.set(TEST_CONFIG_SECTION, "version", version)
    bucket = s3.create_bucket(TEST_S3_BUCKET)

    _publish_to_s3(config)

    for name in (TEST_S3_KEY, TEST_OUTPUT_FILENAME + "/" + version
                 + "/" + TEST_CHUNKNUM):
        assert bucket.get_key(name).get_contents_as_string() == TEST_LIST
    assert sum(1 for _ in bucket.list()) == 2
    assert capsys.readouterr().out == ("Uploaded to s3: %s\n"
                                       % TEST_CONFIG_SECTION)


def test_publish_to_s3_no_bucket(s3, config, capsys):
    """Test publish_to_s3 when `s3_bucket` config option is empty."""
    config.set(TEST_CONFIG_SECTION, "s3_bucket", "")

    with pytest.raises(SystemExit) as e:
        _publish_to_s3(config)

    assert e.value.code == -1
    assert capsys.readouterr().err == ("Can't upload to s3 without "
                                       "s3_bucket and s3_key\n")


def test_publish_to_s3_no_key(s3, config, capsys):
    """Test publish_to_s3 when `s3_key` config option is empty."""
    config.set(TEST_CONFIG_SECTION, "s3_key", "")

    with pytest.raises(SystemExit) as e:
        _publish_to_s3(config)

    assert e.value.code == -1
    assert capsys.readouterr().err == ("Can't upload to s3 without "
                                       "s3_bucket and s3_key\n")


def test_publish_to_s3_permissions(s3, config, capsys):
    """Test that the expected S3 key permissions are set."""
    bucket = s3.create_bucket(TEST_S3_BUCKET)

    with patch("publish2cloud.CLOUDFRONT_USER_ID", "test-user-id"):
        _publish_to_s3(config)

    for name in (TEST_S3_KEY, TEST_OUTPUT_FILENAME + "/" + TEST_CHUNKNUM):
        assert bucket.get_key(name).get_contents_as_string() == TEST_LIST
    assert sum(1 for _ in bucket.list()) == 2
    assert capsys.readouterr().out == ("Uploaded to s3: %s\n"
                                       % TEST_CONFIG_SECTION)
    # FIXME
    pytest.xfail("key.add_user_grant() does not work with moto")
    for name in (TEST_S3_KEY, TEST_OUTPUT_FILENAME + "/" + TEST_CHUNKNUM):
        grants = bucket.get_key(name).get_acl().acl.grants
        assert len(grants) == 2
        assert grants[0].permission == "FULL_CONTROL"
        assert grants[1].permission == "READ"
        assert grants[1].id == "test-user-id"
