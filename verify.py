"""Check that a note stored by Deft Sync is encrypted with your key.

    TOKEN=<sync token> python verify.py [note path] [--print]

Without a note path, checks the first note that isn't deleted.
"""

import base64
import getpass
import hashlib
import hmac
import json
import os
import sys
import urllib.request

import zstandard
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt as aead_decrypt

SERVER = "https://sync.usedeft.com/api"


def fetch(path, token, key_epoch=None):

    headers = {"Authorization": f"Bearer {token}"}
    if key_epoch is not None:
        headers["x-deft-key-epoch"] = str(key_epoch)

    with urllib.request.urlopen(urllib.request.Request(SERVER + path, headers=headers)) as response:
        return response.read()


def live_rows(token, key_epoch):

    since = 0
    while True:
        page = json.loads(fetch(f"/changes?since={since}", token, key_epoch))
        for row in page["files"]:
            if not row["deleted"]:
                yield row
        if not page["has_more"]:
            return
        since = page["files"][-1]["seq"]


def derive_subkey(master_key, purpose):

    pseudorandom_key = hmac.new(bytes(32), master_key, hashlib.sha256).digest()
    return hmac.new(pseudorandom_key, b"deft-sync-v1:" + purpose + b"\x01", hashlib.sha256).digest()


def unseal(subkey, sealed_message, associated_data, description):

    if sealed_message[:2] not in (b"\x01\x00", b"\x01\x01"):
        sys.exit(f"FAILED: the {description} is not a Deft v1 sealed message")

    flags, nonce, ciphertext = sealed_message[1], sealed_message[2:26], sealed_message[26:]

    try:
        # the two header bytes are bound in ahead of the associated data
        plaintext = aead_decrypt(ciphertext, sealed_message[:2] + associated_data, nonce, subkey)
    except Exception:
        sys.exit(f"FAILED: the {description} does not open (wrong key or altered bytes)")

    if flags == 1:
        # the frames carry no content size, so the streaming call is needed
        plaintext = zstandard.ZstdDecompressor().decompressobj(read_across_frames=True).decompress(plaintext)

    return plaintext


def open_record(master_key, sealed):

    sealed_record = base64.b64decode(sealed)
    record = json.loads(unseal(derive_subkey(master_key, b"record"), sealed_record, b"deft-sync-v1:record", "record"))
    return record["path"], bytes.fromhex(record["blob_id"])


def find_note(master_key, token, key_epoch, wanted_path):

    for row in live_rows(token, key_epoch):
        path, blob_id = open_record(master_key, row["record"])
        if wanted_path is None or path == wanted_path:
            return path, blob_id

    sys.exit("No matching note on the server")


def verify(master_key, token, wanted_path, print_contents):

    key_epoch = json.loads(fetch("/key", token))["key_epoch"]

    path, blob_id = find_note(master_key, token, key_epoch, wanted_path)
    print(f"Record opens under the record key: {path}")

    # fetched by the id inside the sealed record so the server's plaintext row is never trusted
    sealed_blob = fetch(f"/blobs/{blob_id.hex()}", token, key_epoch)
    note_contents = unseal(derive_subkey(master_key, b"content"), sealed_blob, blob_id, "blob")
    print("Blob opens under the content key with its id as associated data")

    if hmac.new(derive_subkey(master_key, b"blobid"), note_contents, hashlib.sha256).digest() != blob_id:
        sys.exit("FAILED: the blob id is not the keyed HMAC of the contents")
    print("Blob id is HMAC-SHA256 of the contents under the blobid key")

    print(f"Verified: {path} ({len(note_contents)} bytes)")

    if print_contents:
        sys.stdout.write(note_contents.decode("utf-8", "replace"))


arguments = [argument for argument in sys.argv[1:] if argument != "--print"]
token = os.environ.get("TOKEN", "").strip()

if len(arguments) > 1 or not token:
    sys.exit(__doc__)

key_hex = getpass.getpass("Your key: ").strip()

try:
    master_key = bytes.fromhex(key_hex)
except ValueError:
    master_key = b""

if len(master_key) != 16:
    sys.exit("FAILED: the key must be 32 hex characters")

verify(master_key, token, arguments[0] if arguments else None, "--print" in sys.argv)
