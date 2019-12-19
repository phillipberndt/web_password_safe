#!/usr/bin/env python3
"""
Script to update the encrypted password database for all registered public
keys.

Usage:
    Pipe JSON into this script. The document should have the format

    {
        "account name": ["principal", "credential", ...],
        ..
        "gmail": ["username", "password"]
        "mybank": ["username", "sub account", "password"]
    }

    The Web UI will display all of those, with the account name highlighted
    and filterable for.
"""
import base64
import fcntl
import json
import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.backends import default_backend

backend = default_backend()


def iter_keys():
    with open("credentials.txt", "r") as credentials_store:
        fcntl.lockf(credentials_store.fileno(), fcntl.LOCK_SH)
        for line in credentials_store:
            try:
                key_id, credential_id, x, y, public_key = line.strip().split(";")
            except ValueError:
                continue

            public_key = serialization.load_der_public_key(base64.b64decode(public_key), backend)
            yield key_id, credential_id, public_key


def main():
    data = sys.stdin.read().encode()

    key = aead.AESGCM.generate_key(bit_length=256)
    aesgcm = aead.AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, b'')

    data = {
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
        "key": "",
    }

    for key_id, credential_id, public_key in iter_keys():
        print("Encrypt for %s" % key_id)
        kct = public_key.encrypt(key,
                                 padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                              algorithm=hashes.SHA256(),
                                              label=None))
        data["key"] = base64.b64encode(kct).decode()
        with open("database/%s" % credential_id.replace("/", "_"), "w") as out:
            out.write(json.dumps(data))


if __name__ == "__main__":
    main()
