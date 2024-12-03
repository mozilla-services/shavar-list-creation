#!/usr/bin/env python

import os
import kinto_http
import hashlib
import pathlib
import uuid

from settings import config

from constants import WEBKIT_LISTS_DIR

def get_config_if_env(env_var, config_section, config_option, fallback=""):
    """
    Return the config value if the environment variable exists; otherwise, return the fallback.
    """
    if env_var in os.environ:
        return os.environ[env_var]
    return config.get(config_section, config_option, fallback=fallback)

def get_file_hash(list_path):
    with open(list_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

SERVER = get_config_if_env("SERVER", "main", "remote_settings_url")
BUCKET = "main-workspace"
COLLECTION = "tracking-protection-lists-ios"
AUTHORIZATION = get_config_if_env("AUTHORIZATION", "main", "remote_settings_authorization")
ENVIRONMENT = os.getenv("ENVIRONMENT", "local").lower()
DRY_RUN = os.getenv("DRY_RUN", "0") in "1yY"

def publish2rs():
    client = kinto_http.Client(
        server_url=SERVER,
        auth=AUTHORIZATION,
        bucket=BUCKET,
        collection=COLLECTION,
        dry_mode=DRY_RUN
    )

    remote_attachments = {
        r["name"]: {"id": r["id"], "hash": r["attachment"]["hash"]}
        for r in client.get_records()
    }

    local_attachments = {
        file.stem: get_file_hash(file)
        for file in pathlib.Path(WEBKIT_LISTS_DIR).iterdir()
    }

    # Determine records to create, update, or delete
    # by comparing the attachment sha256 hashes.
    to_create = []
    to_update = []
    for name, hash in local_attachments.items():
        remote_attachment = remote_attachments.pop(name, None)
        if remote_attachment is None:
            to_create.append({"name": name})
        elif remote_attachment["hash"] != hash:
            to_update.append({"id": remote_attachment["id"], "name": name})
    # Remaining records in `remote_attachments` are to be deleted.
    to_delete = [{"id": record["id"]} for _, record in remote_attachments.items()]

    # Print changes
    print("Changes to apply:")
    print(f"To create: {to_create}")
    print(f"To update: {to_update}")
    print(f"To delete: {to_delete}")

    has_pending_changes = (len(to_create) + len(to_update) + len(to_delete)) > 0
    if not has_pending_changes:
        print("Records are in sync. Nothing to do ✅.")
        return os.EX_OK

    # Batch delete operations.
    # NOTE: Attachment deletion is implicit when deleting a record.
    with client.batch() as batch:
        for record in to_delete:
            batch.delete_record(id=record["id"])

    # Adding, updating attachments on client
    # since batch operations are not supported.
    for record in to_create:
        id = str(uuid.uuid4())
        filepath = f"{WEBKIT_LISTS_DIR}/{record['name']}.json"
        client.add_attachment(id=id, data={"name": record["name"]}, filepath=filepath)
    for record in to_update:
        filepath = f"{WEBKIT_LISTS_DIR}/{record['name']}.json"
        client.add_attachment(id=record["id"], filepath=filepath)


    if ENVIRONMENT == "dev":
        # Self approve changes on DEV.
        client.approve_changes(message="r+")
        print("Changes applied to dev server ✅")
    else:
        # Request review.
        print("Request review...", end="")
        client.request_review(message="r?")
        print("✅")