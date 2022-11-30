#!/usr/bin/env python3
import argparse
import socket
from time import sleep

from nacl.encoding import HexEncoder
from nacl.hash import sha256
from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey

from config import METADATA_SIZE, SESSION_KEY_SIZE, SIGNATURE_SIZE, MAX_DATA_SIZE
from utility import allowed_ports, decrypt_and_verify, sign_hash


def main():
    parser = argparse.ArgumentParser("Client application")
    parser.add_argument("--host", default="localhost", help="Location of server")
    parser.add_argument(
        "--port",
        type=allowed_ports,
        default=8000,
        help="Port that server is running on",
    )
    parser.add_argument("--user", help="Name of the user logging in")
    args = parser.parse_args()

    # key used to decrypt messages
    private_key = PrivateKey(
        open(f"./key_pairs/{args.user}", encoding="utf-8").read(), HexEncoder
    )
    # key used to sign messages
    signing_key = SigningKey(
        open(f"./key_pairs/{args.user}_dsa", encoding="utf-8").read(), HexEncoder
    )
    # key used to encrypt messages for the server
    server_public_key = PublicKey(
        open("./key_pairs/server.pub", encoding="utf-8").read(), HexEncoder
    )
    # key used to verify messages from the server
    verify_key = VerifyKey(
        open("./key_pairs/server_dsa.pub", encoding="utf-8").read(), HexEncoder
    )

    box = Box(private_key, server_public_key)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((args.host, args.port))

    s.send(bytes(args.user, "utf-8"))

    # challenge
    print(Box.NONCE_SIZE + METADATA_SIZE + SIGNATURE_SIZE)
    message = s.recv(Box.NONCE_SIZE + METADATA_SIZE + SIGNATURE_SIZE)
    print("Received challenge from server")
    decrypted_nonce = decrypt_and_verify(message, box, verify_key)

    # response
    signed_message = sign_hash(decrypted_nonce, signing_key)
    print("Sending response to server")
    s.send(signed_message + decrypted_nonce)

    # session key
    message = s.recv(SESSION_KEY_SIZE + METADATA_SIZE + SIGNATURE_SIZE)
    if not message:
        print("Unsuccessful authentication to server")
        return
    print("Successfully authenticated to server")
    session_key = decrypt_and_verify(message, box, verify_key)

    print(f"Future communication uses session key {session_key}")

    message = s.recv(MAX_DATA_SIZE)
    print(message.decode())

    inp = ""
    while inp != "q":
        pass

if __name__ == "__main__":
    main()
