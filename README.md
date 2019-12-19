# Password store
This is a simple safe password store. The idea is to populate it from a secure
place, like your desktop, by transforming whatever means you use to store
passwords (e.g. a GnuPG encrypted text file) into a JSON document and
encrypting it, and then use a web client, protected by a WebAuthN, to retrieve
the passwords.

This primarily is an experiment to learn about the WebCrypto and WebAuthN APIs.
I cannot guarantee safety for production; see below for implementation details.

## Setup
Install `server.py` somewhere. Via pip, install
```text
cbor2
cryptography
flask
```
and setup your favorite WSGI server to serve the application via HTTPS. Do not
use multiple processes; threads should be ok, but not required either if you
are the only user.

Set `ALLOW_REGISTRATION` to `True` in `server.py` and access the page from your
phone or another device that supports hardware tokens. The device should
automatically register, and a popup confirm that it did. Disable registration
again. Check `credentials.txt` for the device, and update the identifier in the
first column.

Now you can run `update.py` to feed data into the database. The syntax is
explained at the top of `update.py` itself.

Finally, open the page again in your web browser. You will now be able to
retrieve your passwords or other credentials.

## Cryptography
I do not claim that using this is safe, as I am no expert on cryptography. To
my best knowledge, it is though. The design is the following:

1. The browser generates a public/private key pair and stores the private key in
   secure storage. This is used for WebAuthN registration with the server. This
   key pair is used exclusively for authentication against the server. The code
   uses P-256/SHA256 for this. (I know, bad choice according to some, but it's
   the best supported curve.)
2. Upon registration, the server stores the public key and generates a key pair,
   RSA with 2048 bits this time, of its own. The private key is passed to the
   browser, which stores it in an IndexedDB. This backend store allows to open
   the private key in such a way that it can be used from JavaScript for
   decryption, but not serialized or copied out of the browser. The server stores
   both public keys generated thus far.
3. Upon updating the database, the update script generates a AES key with 256
   bits length. This key is used in GCM mode to encrypt the database. Per
   registered client, the key is encrypted using the public key that the server
   generated, and the AES-GCM cyphertext, nonce, and encrypted key are stored.
4. A client whishing to access the data authenticates to the server via WebAuthN.
   The server then replies with the object stored before. The web browser uses
   the stored private key to decrypt the AES key, and decrypts the database
   itself. The data is stored in a local variable.

The weakest point in this setup should be the browser, in which extensions can
access the DOM tree of the document rendering the passwords.
