import configparser
import hashlib
import os
import requests
import sys
import tempfile
import math

import boto.s3.connection
import boto.s3.key

from requests.auth import HTTPBasicAuth

from constants import (
    DEFAULT_DISCONNECT_LIST_CATEGORIES,
    DNT_SECTIONS,
    VERS_LARGE_ENTITIES_SEPARATION_STARTED,
    LIST_TYPE_ENTITY,
    LIST_TYPE_TRACKER,
    LIST_TYPE_PLUGIN,
    PLUGIN_SECTIONS,
    PRE_DNT_SECTIONS,
    LARGE_ENTITIES_SECTIONS,
    ENTITYLIST_SECTIONS
)
from packaging import version as p_version

from settings import (
    config as CONFIG,
    rs_auth_method,
    BearerAuth,
    environment,
    shared_state
)

from utils import should_skip_section_for_version

from kinto_http import Client, BearerTokenAuth, KintoException

try:
    REMOTE_SETTINGS_URL = ''
    if os.environ.get('SERVER', None):
        REMOTE_SETTINGS_URL = CONFIG.get('main', 'remote_settings_url')
    REMOTE_SETTINGS_BUCKET = CONFIG.get('main', 'remote_settings_bucket')
    REMOTE_SETTINGS_COLLECTION = CONFIG.get(
        'main', 'remote_settings_collection'
    )
    REMOTE_SETTINGS_PATH = ('/buckets/{bucket_name}'
                                   + '/collections/{collection_name}')

    REMOTE_SETTINGS_AUTH = ''
    if os.environ.get('AUTHORIZATION', None):
        REMOTE_SETTINGS_AUTH = CONFIG.get('main', 'remote_settings_authorization')

    # We can remove the use of BearerAuth() once we switch to kinto-http
    if rs_auth_method == 'token':
        REMOTE_SETTINGS_AUTH = BearerAuth(REMOTE_SETTINGS_AUTH)
    elif rs_auth_method == 'userpass':
        REMOTE_SETTINGS_AUTH = HTTPBasicAuth(*tuple(REMOTE_SETTINGS_AUTH.split(":", maxsplit=1)))

    CLOUDFRONT_USER_ID = os.environ.get('CLOUDFRONT_USER_ID', None)

except configparser.NoOptionError as err:
    REMOTE_SETTINGS_URL = ''
    REMOTE_SETTINGS_AUTH = None
    REMOTE_SETTINGS_BUCKET = ''
    REMOTE_SETTINGS_COLLECTION = ''
    REMOTE_SETTINGS_PATH = ''
    CLOUDFRONT_USER_ID = None

client = Client(
    server_url=REMOTE_SETTINGS_URL,
    bucket=REMOTE_SETTINGS_BUCKET,
    collection=REMOTE_SETTINGS_COLLECTION,
    auth=REMOTE_SETTINGS_AUTH
)

def chunk_metadata(fp):
    header = fp.readline().decode().rstrip('\n')
    chunktype, chunknum, hash_size, data_len = header.split(':')
    return dict(
        type=chunktype, num=chunknum, hash_size=hash_size, len=data_len,
        checksum=hashlib.sha256(fp.read()).hexdigest()
    )


def make_record_url_remote_settings(id):
    remote_settings_record_url = (
        REMOTE_SETTINGS_URL
        + REMOTE_SETTINGS_PATH.format(
            bucket_name=REMOTE_SETTINGS_BUCKET,
            collection_name=REMOTE_SETTINGS_COLLECTION)
    )
    return remote_settings_record_url + '/records/{record_id}'.format(record_id=id)


def get_record_remote_settings(id):
    try:
        record = client.get_record(id=id)
        print('{0} - Record exists in Remote Settings'
            .format(id))

        return record
    except KintoException as e:
        if e.response.status_code == 404 :
            print('{0} -  Record does not exist in Remote Settings'
            .format(id))
        else:
            print('{0} -  There was a problem getting record from '
                    'Remote Settings: {1}'.format(id, e))
        return None


def put_new_record_remote_settings(config, section, data):
    try:
        rec_resp = client.update_record(id=data['id'],
            data=data)

        if not rec_resp:
            print('Failed to create/update record for %s. Error: %s' %
                (data['Name'], rec_resp.content.decode()))
            return rec_resp
    except KintoException as e:
        print('Failed to create/update record for {0}. Error: {1}'
                .format(data['Name'], e))

    record_url = make_record_url_remote_settings(data['id'])
    attachment_url = record_url + '/attachment'
    files = [('attachment', open(config.get(section, 'output'), 'rb'))]
    att_resp = requests.post(
        attachment_url, files=files, auth=REMOTE_SETTINGS_AUTH)
    return att_resp


def check_upload_config(config, section, option):
    if config.has_option(section, option):
        # if it exists, the specific section's upload config is prioritized
        return config.getboolean(section, option)

    if config.has_option('main', option):
        # if it exists, the default config is used
        return config.getboolean('main', option)
    return False


def new_data_to_publish_to_remote_settings(config, section, new, version=None):
    remote_settings_config_exists = (REMOTE_SETTINGS_URL
                                     and REMOTE_SETTINGS_BUCKET
                                     and REMOTE_SETTINGS_COLLECTION
                                     and REMOTE_SETTINGS_PATH
                                     and REMOTE_SETTINGS_AUTH)
    if not remote_settings_config_exists:
        print('Missing config(s) for Remote Settings')
        return False

    record_id = config.get(section, 'output')

    record_name = record_id
    if version is not None:
        record_name = f'{record_id}-{math.trunc(version.release[0])}'

        if shared_state.latest_supported_version - version.release[0] > int(config.get('main', 'num_supported_versions')):
            deleteRecordFromRemoteSettings(record_name)

            # Since we don't support this version, we can return False
            return False

        if shared_state.oldest_supported_version == version.release[0]:
            # We want to update the oldest supported version with a new filter_expression
            return True

    # Check to see if update is needed on Remote Settings
    record = get_record_remote_settings(record_name)

    if version is None:
        # We need to check if the filter_expression needs to be updated for the
        # nightly records. The filter_expression needs to be updated if the
        # latest supported version has changed
        if record.get('data')['filter_expression'] != f'env.version|versionCompare("{shared_state.latest_supported_version}.0a1") <= 0':
            return True

    return not (record and record.get('data')['Checksum'] == new['checksum'])


def new_data_to_publish_to_s3(config, section, new):
    """Determine whether a list stored on S3 needs to be updated.

    Return True if:
      - The checksum of the new list is not equal to that of the list
        currently stored on S3
      - The list is new and has not been uploaded to S3 yet
    """
    # Get the metadata for our old chunk
    conn = boto.s3.connection.S3Connection()
    bucket = conn.get_bucket(config.get('main', 's3_bucket'))
    s3key = config.get(section, 'output')
    if config.has_option(section, 's3_key'):
        s3key = config.get(section, 's3_key')
        if s3key == "":
            raise ValueError("Configuration section '%s': 's3_key' "
                             "option cannot be empty." % section)
    key = bucket.get_key(s3key)
    if key is None:
        # Most likely a new list
        print('{0} looks like it hasn\'t been uploaded to '
              's3://{1}/{2}'.format(section, bucket.name, s3key))
        return True
    current = tempfile.TemporaryFile()
    key.get_contents_to_file(current)
    key.set_acl('bucket-owner-full-control')
    if CLOUDFRONT_USER_ID is not None:
        key.add_user_grant('READ', CLOUDFRONT_USER_ID)
    current.seek(0)

    old = chunk_metadata(current)
    current.close()

    if old['checksum'] != new['checksum']:
        return True

    return False


def publish_to_s3(config, section, chunknum):
    bucket = config.get('main', 's3_bucket')
    # Override with list specific bucket if necessary
    if config.has_option(section, 's3_bucket'):
        bucket = config.get(section, 's3_bucket')

    key = os.path.basename(config.get(section, 'output'))
    # Override with list specific value if necessary
    if config.has_option(section, 's3_key'):
        key = config.get(section, 's3_key')

    versioning_needed = (
        config.has_option(section, 'versioning_needed')
        and config.getboolean(section, 'versioning_needed')
    )
    if versioning_needed and config.has_option(section, 'version'):
        chunk_key = os.path.join(
            config.get(section, os.path.basename('output')),
            config.get(section, 'version'),
            str(chunknum)
        )
    else:
        chunk_key = os.path.join(
            config.get(section, os.path.basename('output')),
            str(chunknum)
        )

    if not bucket or not key:
        sys.stderr.write(
            'Can\'t upload to s3 without s3_bucket and s3_key\n')
        sys.exit(-1)
    output_filename = config.get(section, 'output')
    conn = boto.s3.connection.S3Connection()
    bucket = conn.get_bucket(bucket)
    for key_name in (chunk_key, key):
        k = boto.s3.key.Key(bucket)
        k.key = key_name
        k.set_contents_from_filename(output_filename)
        k.set_acl('bucket-owner-full-control')
        if CLOUDFRONT_USER_ID is not None:
            k.add_user_grant('READ', CLOUDFRONT_USER_ID)
    print('Uploaded to s3: %s' % section)


def publish_to_remote_settings(config, section, chunknum, version):
    list_type = ''
    categories = []
    excluded_categories = []
    if (section in PRE_DNT_SECTIONS or section in DNT_SECTIONS):
        list_type = LIST_TYPE_TRACKER
        if config.has_option(section, 'categories'):
            list_categories = config.get(section, 'categories').split(',')
        else:
            list_categories = DEFAULT_DISCONNECT_LIST_CATEGORIES
        categories = []
        for x in list_categories:
            categories.extend(x.split('|'))

        if config.has_option(section, 'excluded_categories'):
            excluded = config.get(
                    section, 'excluded_categories'
                ).split(',')
            for x in excluded:
                excluded_categories.extend(x.split('|'))
    elif (section in PLUGIN_SECTIONS):
        list_type = LIST_TYPE_PLUGIN
    elif (section in ENTITYLIST_SECTIONS):
        list_type = LIST_TYPE_ENTITY

    list_name = config.get(section, 'output')
    chunk_file = chunk_metadata(open(config.get(section, 'output'), 'rb'))

    # Note: versionCompare treats beta as less than release, i.e. 128.0a1 < 128.0b1 < 128.0
    # To account for this, we should compare the versions with Nightly
    #
    # For example, if the client is fx129.0b1:
    #
    # If we used release to compare:
    #   The filter expression match would be 128.0 <= client < 129.0 ===> list for version 128 would be served.
    #   This is incorrect
    #
    # Instead, using nightly to compare:
    #   The filter expression match is 129.0a1 <= client < 130.0a1 ===> list for version 129 is served
    #   This is the expected behaviour

    # This is the default list (used for the master branch for Nightly)
    record_data = {
        'id': list_name,
        'Categories': categories,
        'ExcludedCategories': excluded_categories,
        'Type': list_type,
        'Name': list_name,
        'Checksum': chunk_file['checksum'],
        'Version': chunknum,
        # The default master branch is the latest list in shavar-prod-lists, we use filter_expression
        # to make sure only the latest fx versions use this list by setting the expression to greater than
        # the "latest_supported_version" + 1 .0a1, since the latest_supported_version is the highest version number in
        # the shavar prod lists branch names
        'filter_expression': f'env.version|versionCompare("{shared_state.latest_supported_version+1}.0a1") >= 0'
    }

    # Add fields for versioned lists
    if version is not None:
        record_data['id'] = f'{list_name}-{math.trunc(version.release[0])}'

        next_version = version.release[0] + 1
        if version.release[0] == shared_state.oldest_supported_version:
            # For all unsupported fx versions, we serve the oldest supported version
            # Note: we have to compare against the nightly version, since 128.0a1 < 128.0b1 < 128.0
            record_data['filter_expression'] = f'env.version|versionCompare("{version}a1") <= 0'
        else:
            # This filter_expression makes sure that a supported version is only given it's exact
            # versioned list
            # Note: we need to add a .0 to the next_version, since version.release[0] is an integer
            record_data['filter_expression'] = f'env.version|versionCompare("{version}a1") >= 0 && env.version|versionCompare("{next_version}.0a1") < 0'

    put_new_record_remote_settings(config, section, record_data)
    print('Uploaded to remote settings: %s' % list_name)

def publish_to_cloud(config, chunknum, check_versioning=None):
    # Optionally upload to S3. If s3_upload is set, then s3_bucket and s3_key
    # must be set.
    for section in config.sections():
        if section == 'main':
            continue

        # Set default version as None
        version = None
        if check_versioning:
            versioning_needed = (
                config.has_option(section, 'versioning_needed')
                and config.getboolean(section, 'versioning_needed')
            )
            if not versioning_needed:
                continue

            version = p_version.parse(config.get(section, 'version'))
            skip_section = should_skip_section_for_version(config, section, version.release[0])

            if skip_section:
                continue

            skip_large_entity_separation = (
                version.release[0] < VERS_LARGE_ENTITIES_SEPARATION_STARTED
                and section in LARGE_ENTITIES_SECTIONS
            )
            if skip_large_entity_separation:
                continue
            print('Publishing versioned lists for: ' + section)

        upload_to_s3 = check_upload_config(config, section, 's3_upload')

        upload_to_remote_setting = check_upload_config(
            config, section, 'remote_settings_upload'
        )

        if not upload_to_s3 and not upload_to_remote_setting:
            print('Upload to Remote Setting and S3 disabled.')
            return

        with open(config.get(section, 'output'), 'rb') as blob:
            new = chunk_metadata(blob)

        if upload_to_s3:
            s3_upload_needed = new_data_to_publish_to_s3(config, section, new)
        else:
            s3_upload_needed = False

        try:
            rs_upload_needed = new_data_to_publish_to_remote_settings(
                config, section, new, version
            )
        except (requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout):
            print('Connection timed out on Remote Settings.')
            rs_upload_needed = False
        if not s3_upload_needed and not rs_upload_needed:
            print('No new data to publish for %s' % section)
            continue

        if s3_upload_needed and upload_to_s3:
            publish_to_s3(config, section, chunknum)
        else:
            print('Skipping S3 upload for %s' % section)

        if rs_upload_needed and upload_to_remote_setting:
            publish_to_remote_settings(config, section, chunknum, version)
        else:
            print('Skipping Remote Settings upload for %s' % section)


def request_rs_review():
    if check_upload_config(
            CONFIG, 'main', 'remote_settings_upload'
        ) == False:
        print("\n*** Remote Settings upload is not enabled for this run, no reviews are required ***\n")
        return

    rs_collection_url = REMOTE_SETTINGS_URL + \
         REMOTE_SETTINGS_PATH.format(
            bucket_name=REMOTE_SETTINGS_BUCKET,
            collection_name=REMOTE_SETTINGS_COLLECTION)

    # Check if we need to send in a request for review
    rs_collection = client.get_collection();

    if rs_collection:
        # If any data was published, we want to request review for it
        # status can be one of "work-in-progress", "to-sign" (approve), "to-review" (request review)
        if rs_collection['data']['status'] == "work-in-progress":
            if environment == "dev":
                print("\n*** Dev server does not require a review, approving changes ***\n")
                # review not enabled in dev, approve changes
                client.patch_collection(data={"status": "to-sign"});
            else:
                print("\n*** Requesting review for updated/created records ***\n")
                client.patch_collection(data={"status": "to-review"});
        else:
            print("\n*** No changes were made, no new review request is needed ***\n")
    else:
        print("\n*** Error while fetching collection status ***\n")


# Helper function that clears all records in dev
def deleteAllRecordsInDev():
    if environment == "dev":
        try:
            client.delete_records()
        except KintoException as e:
            print('!!!! Failed to all delete records: {0}!!!!'.format(e))


# Delete all records related to version 'ver'
def deleteRecordFromRemoteSettings(list_id):
    print(f'\n*** Deleting record with id {list_id} ***')
    try:
        client.delete_record(id=list_id)
    except KintoException as e:
        error_info = e.response.json()
        if 'errno' in error_info and error_info['errno'] == 110:
            print(f"{list_id} not found\n")
        else:
            # Re-raise the exception if it's not errno 110
            raise
