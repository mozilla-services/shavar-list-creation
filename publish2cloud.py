import configparser
import hashlib
import os
import requests
import sys
import tempfile

import boto.s3.connection
import boto.s3.key

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
    ENTITYLIST_SECTIONS,
)
from packaging import version as p_version

CONFIG = configparser.ConfigParser(os.environ)
CONFIG.read(['shavar_list_creation.ini'])
try:
    REMOTE_SETTINGS_URL = ''
    if os.environ.get('SHAVAR_REMOTE_SETTINGS_URL', None):
        REMOTE_SETTINGS_URL = CONFIG.get('main', 'remote_settings_url')
    REMOTE_SETTINGS_BUCKET = CONFIG.get('main', 'remote_settings_bucket')
    REMOTE_SETTINGS_COLLECTION = CONFIG.get(
        'main', 'remote_settings_collection'
    )
    REMOTE_SETTINGS_RECORD_PATH = ('/buckets/{bucket_name}'
                                   + '/collections/{collection_name}/records')
    REMOTE_SETTINGS_AUTH = ('', '')
    auth_config_exists = (
        os.environ.get('SHAVAR_REMOTE_SETTINGS_USERNAME', None)
        and os.environ.get('SHAVAR_REMOTE_SETTINGS_PASSWORD', None)
    )
    if auth_config_exists:
        REMOTE_SETTINGS_AUTH = (
            CONFIG.get('main', 'remote_settings_username'),
            CONFIG.get('main', 'remote_settings_password')
        )
    CLOUDFRONT_USER_ID = os.environ.get('CLOUDFRONT_USER_ID', None)

except configparser.NoOptionError as err:
    REMOTE_SETTINGS_URL = ''
    REMOTE_SETTINGS_AUTH = None
    REMOTE_SETTINGS_BUCKET = ''
    REMOTE_SETTINGS_COLLECTION = ''
    REMOTE_SETTINGS_RECORD_PATH = ''
    CLOUDFRONT_USER_ID = None


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
        + REMOTE_SETTINGS_RECORD_PATH.format(
            bucket_name=REMOTE_SETTINGS_BUCKET,
            collection_name=REMOTE_SETTINGS_COLLECTION)
    )
    return remote_settings_record_url + '/{record_id}'.format(record_id=id)


def get_record_remote_settings(id):
    record_url = make_record_url_remote_settings(id)
    resp = requests.get(record_url, auth=REMOTE_SETTINGS_AUTH, timeout=10)
    if not resp:
        print('{0} looks like it hasn\'t been uploaded to '
              'Remote Settings'.format(id))
        return None
    record = resp.json()['data']
    return record


def put_new_record_remote_settings(config, section, data):
    record_url = make_record_url_remote_settings(data['id'])
    rec_resp = requests.put(
        record_url, json={'data': data}, auth=REMOTE_SETTINGS_AUTH)

    if not rec_resp:
        print('Failed to create/update record for %s. Error: %s' %
              (data['Name'], rec_resp.content.decode()))
        return rec_resp

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


def new_data_to_publish_to_remote_settings(config, section, new):
    remote_settings_config_exists = (REMOTE_SETTINGS_URL
                                     and REMOTE_SETTINGS_BUCKET
                                     and REMOTE_SETTINGS_COLLECTION
                                     and REMOTE_SETTINGS_RECORD_PATH
                                     and REMOTE_SETTINGS_AUTH)
    if not remote_settings_config_exists:
        print('Missing config(s) for Remote Settings')
        return False

    # Check to see if update is needed on Remote Settings
    record = get_record_remote_settings(config.get(section, 'output'))

    rs_upload_needed = True
    if record and record.get('Checksum') == new['checksum']:
        rs_upload_needed = False
    return rs_upload_needed


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


def publish_to_remote_settings(config, section):
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
    record_data = {
        'id': list_name,
        'Categories': categories,
        'ExcludedCategories': excluded_categories,
        'Type': list_type,
        'Name': list_name,
        'Checksum': chunk_file['checksum']
    }
    put_new_record_remote_settings(config, section, record_data)
    print('Uploaded to remote settings: %s' % list_name)


def publish_to_cloud(config, chunknum, check_versioning=None):
    # Optionally upload to S3. If s3_upload is set, then s3_bucket and s3_key
    # must be set.
    for section in config.sections():
        if section == 'main':
            continue

        if check_versioning:
            versioning_needed = (
                config.has_option(section, 'versioning_needed')
                and config.getboolean(section, 'versioning_needed')
            )
            if not versioning_needed:
                continue

            version = p_version.parse(config.get(section, 'version'))
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
                config, section, new
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
            publish_to_remote_settings(config, section)
        else:
            print('Skipping Remote Settings upload for %s' % section)
