shavar-list-creation
====================

[![Build Status](https://circleci.com/gh/mozilla-services/shavar-list-creation/tree/main.svg?style=shield)](https://circleci.com/gh/mozilla-services/shavar-list-creation/tree/main)
[![Coverage](https://circleci.com/api/v1.1/project/github/mozilla-services/shavar-list-creation/latest/artifacts/0/coverage.svg?branch=main)](https://circleci.com/api/v1.1/project/github/mozilla-services/shavar-list-creation/latest/artifacts/0/htmlcov/index.html?branch=main)

This script fetches blocklist `.json` from urls (such as
[shavar-prod-lists](https://github.com/mozilla-services/shavar-prod-lists)) and
generates safebrowsing-compatible digest list files to be served by
[shavar](https://github.com/mozilla-services/shavar).

# Requirements

* python &geq; 3.6
* (optional) virtualenv and/or virtualenvwrapper

# Run

1. (optional) Make a virtualenv for the project and activate it:

    ```
    virtualenv -p python3.8 shavar-list-creation
    source shavar-list-creation/bin/activate
    ```

2. Install required libraries:

    ```
    pip install -r requirements.txt
    ```

3. Copy the `sample_shavar_list_creation.ini` file to
   `shavar_list_creation.ini`:

    ```
    cp sample_shavar_list_creation.ini shavar_list_creation.ini
    ```

4. Run the unit tests (currently under development):

    ```
    python -m pytest -v --cov=. --cov-branch
    ```

5. Run the `lists2safebrowsing.py` script:

    ```
    ./lists2safebrowsing.py
    ```

# Usage
This is run by a Jenkins deployment job every 30 minutes that:

1. Checks out this repository
2. Checks out the [shavar-list-creation-config](https://github.com/mozilla-services/shavar-list-creation-config/) repository
3. Copies `stage.ini` or `prod.ini` to `shavar_list_creation.ini`
4. Runs `python lists2safebrowsing.py`, which uploads updated safebrowsing list files to S3 for [shavar](https://github.com/mozilla-services/shavar).
