import ConfigParser
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
    LIST_TYPE_ENTITY,
    LIST_TYPE_TRACKER,
    LIST_TYPE_PLUGIN,
    PLUGIN_SECTIONS,
    PRE_DNT_SECTIONS,
    WHITELIST_SECTIONS,
)

CONFIG = ConfigParser.SafeConfigParser(os.environ)
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
except ConfigParser.NoOptionError as err:
    REMOTE_SETTINGS_URL = ''
    REMOTE_SETTINGS_AUTH = None
    REMOTE_SETTINGS_BUCKET = ''
    REMOTE_SETTINGS_COLLECTION = ''
    REMOTE_SETTINGS_RECORD_PATH = ''


def chunk_metadata(fp):
    # Read the first 25 bytes and look for a new line.  Since this is a file
    # formatted like a chunk, a end of the chunk header(a newline) should be
    # found early.
    header = fp.read(25)
    eoh = header.find('\n')
    chunktype, chunknum, hash_size, data_len = header[:eoh].split(':')
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
    resp = requests.get(record_url, auth=REMOTE_SETTINGS_AUTH)
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
              (data['Name'], rec_resp.content))
        return rec_resp

    attachment_url = record_url + '/attachment'
    files = [('attachment', open(config.get(section, 'output'), 'rb'))]
    att_resp = requests.post(
        attachment_url, files=files, auth=REMOTE_SETTINGS_AUTH)
    return att_resp


def check_upload_remote_settings_config(config, section):
    if config.has_option(section, 'remote_settings_upload'):
        # if it exists, the specfic section's upload config is prioritized
        return config.getboolean(section, 'remote_settings_upload')

    if config.has_option('main', 'remote_settings_upload'):
        # if it exists, the deafult config is used
        return config.getboolean('main', 'remote_settings_upload')
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
    # Get the metadata for our old chunk

    # If necessary fetch the existing data from S3, otherwise open a local file
    if ((config.has_option('main', 's3_upload')
         and config.getboolean('main', 's3_upload'))
        or (config.has_option(section, 's3_upload')
            and config.getboolean(section, 's3_upload'))):
        conn = boto.s3.connection.S3Connection()
        bucket = conn.get_bucket(config.get('main', 's3_bucket'))
        s3key = config.get(section, 's3_key') or config.get(section, 'output')
        key = bucket.get_key(s3key)
        if key is None:
            # most likely a new list
            print('{0} looks like it hasn\'t been uploaded to '
                  's3://{1}/{2}'.format(section, bucket.name, s3key))
            key = boto.s3.key.Key(bucket)
            key.key = s3key
            key.set_contents_from_string('a:1:32:32\n' + 32 * '1')
        current = tempfile.TemporaryFile()
        key.get_contents_to_file(current)
        current.seek(0)
    else:
        current = open(config.get(section, 'output'), 'rb')

    old = chunk_metadata(current)
    current.close()

    s3_upload_needed = False
    if old['checksum'] != new['checksum']:
        s3_upload_needed = True

    return s3_upload_needed


def publish_to_s3(config, section, chunknum):
    bucket = config.get('main', 's3_bucket')
    # Override with list specific bucket if necessary
    if config.has_option(section, 's3_bucket'):
        bucket = config.get(section, 's3_bucket')

    key = os.path.basename(config.get(section, 'output'))
    # Override with list specific value if necessary
    if config.has_option(section, 's3_key'):
        key = config.get(section, 's3_key')

    chunk_key = os.path.join(
        config.get(section, os.path.basename('output')), str(chunknum))

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
    elif (section in WHITELIST_SECTIONS):
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
            print('Publishing versioned lists for: ' + section)

        upload_to_s3 = True
        if (config.has_option(section, "s3_upload")
                and not config.getboolean(section, "s3_upload")):
            upload_to_s3 = False

        upload_to_remote_setting = check_upload_remote_settings_config(
            config, section)

        if not upload_to_s3 and not upload_to_remote_setting:
            print('Upload to Remote Setting and S3 disabled.')
            return

        with open(config.get(section, 'output'), 'rb') as blob:
            new = chunk_metadata(blob)
            s3_upload_needed = new_data_to_publish_to_s3(config, section, new)
            try:
                rs_upload_needed = new_data_to_publish_to_remote_settings(
                    config, section, new
                )
            except requests.exceptions.ConnectionError as exc:
                print('Connection Error on Remote Settings.')
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
