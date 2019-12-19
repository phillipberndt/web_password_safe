#!/usr/bin/env python3
"""
Password database web server

This is the web server backing the password database. Set it up using your
favorite WSGI server. Note that the server must be using HTTPS for this to
work. Also, make sure that ./credentials.txt is writeable and ./database/
is readable to this script.

The server stores challenges in a local dictionary. If you set up WSGI to
use multiple processes this won't work, at least not in a round-robin setup.
Either adjust the type of the challenges variable or go for multi-threaded
instead.

When registering, set ALLOW_REGISTRATION to True. For security reasons this
is hard-coded.
"""
import base64
import fcntl
import hashlib
import io
import json
import struct
import time

import cbor2
import flask

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from flask import request


ALLOW_REGISTRATION = False

app = flask.Flask(__name__)
backend = default_backend()
challenges = {}


def clean_challenges():
    for challenge, timer in list(challenges.items()):
        if timer < time.time() - 180:
            del challenges[challenge]
    if len(challenges) > 100:
        raise ValueError("Too many challenges.")


def verify_challenge(challenge):
    timer = challenges.pop(challenge, None)
    if not timer:
        return False
    if timer > time.time() - 180:
        return False


def parse_auth_data(auth_data):
    # See https://w3c.github.io/webauthn/#authenticator-data:
    # Offset of credential data is
    # 32 bytes hash + 1 byte flags + 4 bytes sig count + 16 bytes GUID
    # Then there's 2 bytes length of credentialID, 16 bit unsigned BE
    # followed by the actual credentialID.
    # Then follows the publicKey, which is COSE data

    credential_id_length = struct.unpack(">H", auth_data[53:55])[0]
    credential_id = auth_data[55:55 + credential_id_length]
    public_key = cbor2.loads(auth_data[55 + credential_id_length:])

    # Only accept the keys we would like to see
    assert public_key[-1] == 1  # P-256
    assert public_key[3] == -7  # ECDSA with SHA256
    assert public_key[1] == 2   # Elliptic

    return credential_id, public_key


@app.route("/")
def index():
    return flask.render_template("index.html", ALLOW_REGISTRATION=ALLOW_REGISTRATION)


@app.route("/challenge", methods=["POST"])
def challenge():
    clean_challenges()
    with open("/dev/urandom", "rb") as urandom:
        challenge = urandom.read(16)
    challenges[challenge] = time.time()
    return flask.jsonify({"challenge": base64.b64encode(challenge).decode()})


@app.route("/retrieve", methods=["POST"])
def retrieve():
    # Expect a valid WebAuthN
    client_credential_id = request.json["id"]
    auth_data = base64.b64decode(request.json["authenticatorData"])
    client_data_JSON_raw = base64.b64decode(request.json["clientDataJSON"])
    client_data_JSON = json.loads(client_data_JSON_raw.decode())
    verify_challenge(client_data_JSON["challenge"])
    assert client_data_JSON["type"] == "webauthn.get"

    # Restore to full, valid base64. Chrome strips the tailing "="s, because of base64url encoding, which
    # is partially removed in the Javascript in index.html
    client_credential_id = client_credential_id + ("=" * (4 - ((len(client_credential_id) % 4) or 4)))

    # Fetch key from credential store
    with open("credentials.txt", "r") as credentials_store:
        fcntl.lockf(credentials_store.fileno(), fcntl.LOCK_SH)
        for line in credentials_store:
            try:
                key_id, credential_id, x, y, public_key = line.strip().split(";")
            except ValueError:
                continue
            if credential_id == client_credential_id:
                fcntl.lockf(credentials_store.fileno(), fcntl.LOCK_UN)
                break
        else:
            fcntl.lockf(credentials_store.fileno(), fcntl.LOCK_UN)
            raise KeyError("Unknown credentials")

    # Verify signature
    signature = base64.b64decode(request.json["signature"])
    xr = int.from_bytes(base64.b64decode(x), "big")
    yr = int.from_bytes(base64.b64decode(y), "big")
    key = ec.EllipticCurvePublicNumbers(xr, yr, ec.SECP256R1()).public_key(default_backend())
    digest = hashlib.sha256(client_data_JSON_raw).digest()
    signed_data = auth_data + digest
    key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))

    # Return the credential store encrypted for this key
    data = open("database/%s" % client_credential_id.replace("/", "_"), "rb").read()
    response = flask.make_response(data)
    response.headers.set("Content-Type", "application/json")
    return response


@app.route("/register", methods=["POST"])
def register():
    if not ALLOW_REGISTRATION:
        raise RuntimeError()

    # Expect a valid WebAuthN
    attestation_object_raw = base64.b64decode(request.json["attestationObject"])
    attestation_object = cbor2.loads(attestation_object_raw)
    client_data_JSON_raw = base64.b64decode(request.json["clientDataJSON"])
    client_data_JSON = json.loads(client_data_JSON_raw.decode())
    verify_challenge(client_data_JSON["challenge"])
    assert client_data_JSON["type"] == "webauthn.create"
    credential_id, public_key = parse_auth_data(attestation_object["authData"])

    # Generate RSA key pair
    crypto_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=backend)
    crypto_public_key = crypto_private_key.public_key()

    private_der = base64.b64encode(
        crypto_private_key.private_bytes(encoding=serialization.Encoding.DER,
                                         format=serialization.PrivateFormat.PKCS8,
                                         encryption_algorithm=serialization.NoEncryption()))

    public_pem = base64.b64encode(
        crypto_public_key.public_bytes(encoding=serialization.Encoding.DER,
                                       format=serialization.PublicFormat.SubjectPublicKeyInfo))

    with open("credentials.txt", "r+b") as credentials_store:
        fcntl.lockf(credentials_store.fileno(), fcntl.LOCK_EX)
        credentials_store.seek(0, io.SEEK_END)
        credentials_store.write(b"\nUnnamed Key;%s;%s;%s;%s" % (
            base64.b64encode(credential_id),
            base64.b64encode(public_key[-2]),  # x-coordinate
            base64.b64encode(public_key[-3]),  # y-coordinate
            public_pem,
        ))
        fcntl.lockf(credentials_store.fileno(), fcntl.LOCK_UN)

    return flask.jsonify({"pk": private_der.decode()})


@app.after_request
def apply_safety_headers(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    response.headers["Expires"] = "-1"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


if __name__ == "__main__":
    app.run(threaded=True)
