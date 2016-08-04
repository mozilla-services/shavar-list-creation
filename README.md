shavar-list-creation
====================
This script fetches blocklist `.json` from urls (such as
[shavar-prod-lists](https://github.com/mozilla-services/shavar-prod-lists)) and
generates safebrowsing-compatible digest list files to be served by
[shavar](https://github.com/mozilla-services/shavar).

# Requirements
A `shavar_list_creation.ini` file must exist in the same directory that specifies the following parameters. (See `sample_shavar_list_creation.ini` for an example.)

# Run
```
./lists2safebrowsing.py
```

# Usage
This is run by a Jenkins deployment job every 30 minutes that:

1. Checks out this repository
2. Checks out the [shavar-list-creation-config](https://github.com/mozilla-services/shavar-list-creation-config/) repository
3. Copies `stage.ini` or `prod.ini` to `shavar_list_creation.ini`
4. Runs `python lists2safebrowsing.py`, which uploads updated safebrowsing list files to S3 for [shavar](https://github.com/mozilla-services/shavar).
