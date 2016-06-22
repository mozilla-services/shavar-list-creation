shavar-list-creation
====================
    usage: lists2safebrowsing.py

A shavar.ini file must exist in the same directory that specifies the following parameters. See sample_shavar_list_creation.ini for examples.

Commits to shavar-list-exceptions trigger rebuilds of shavar-list-creation like so:

1. A commit is made to https://github.com/mozilla-services/shavar-list-exceptions
2. That commit triggers a Jenkins workflow that will pull down the current exception list
3. Jenkins then pulls down the master codebase from https://github.com/mozilla-services/shavar-list-creation and builds the list
4. The completed list is placed in the s3 bucket for production

This job does not run on a cron. This is OK so long as we're not publishing true incremental updates.
