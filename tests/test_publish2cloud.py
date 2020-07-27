import time

from mock import mock_open, patch

from publish2cloud import chunk_metadata


def test_chunk_metadata():
    """Test getting metadata from the chunk header of a list file."""
    chunknum = int(time.time())
    # Hash of test-track-digest256.dummytracker.org/
    domain_hash = (b"q\xd8Q\xbe\x8b#\xad\xd9\xde\xdf\xa7B\x12\xf0D\xa2"
                   "\xf2\x1d\xcfx\xeaHi\x7f8%\xb5\x99\x83\xc1\x111")
    data = b"a:%d:32:32\n" % chunknum + domain_hash

    with patch("test_publish2cloud.open", mock_open(read_data=data)):
        with open("base-fingerprinting-track-digest256", "rb") as fp:
            metadata = chunk_metadata(fp)

    assert metadata["type"] == "a"
    assert metadata["num"] == str(chunknum)
    assert metadata["hash_size"] == "32"
    assert metadata["len"] == "32"
    assert metadata["checksum"] == ("043493ecb63c5f143a372a5118d04a44df"
                                    "188f238d2b18e6cd848ae413a01090")
