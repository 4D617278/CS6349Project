#!/usr/bin/env python3
import argparse
import socket

from nacl.encoding import HexEncoder
from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey
from nacl.utils import random

from config import HOST, MAX_USERNAME_LEN, SESSION_KEY_SIZE, SIGNATURE_SIZE
from utility import allowed_ports, encrypt_and_sign, get_signature_and_message


def main():
    parser = argparse.ArgumentParser("Client application")
    parser.add_argument(
        "--port", type=allowed_ports, default=8000, help="Port to run server on"
    )
    args = parser.parse_args()

    # key used to decrypt messages
    private_key = PrivateKey(
        open("./key_pairs/server", encoding="utf-8").read(), HexEncoder
    )
    # key used to sign messages
    signing_key = SigningKey(
        open("./key_pairs/server_dsa", encoding="utf-8").read(), HexEncoder
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, args.port))
    print("Waiting for connection")
    s.listen()
    conn, _ = s.accept()

    client_user_bytes = conn.recv(MAX_USERNAME_LEN)
    client_user = client_user_bytes.decode()
    print(f"Received connection request from client {client_user}")

    # key used to encrypt messages for the client
    client_public_key = PublicKey(
        open(f"./key_pairs/{client_user}.pub", encoding="utf-8").read(), HexEncoder
    )
    # key used to verify messages from the client
    verify_key = VerifyKey(
        open(f"./key_pairs/{client_user}_dsa.pub", encoding="utf-8").read(), HexEncoder
    )

    box = Box(private_key, client_public_key)

    # 24 bytes
    nonce = random(Box.NONCE_SIZE)

    # challenge
    message = encrypt_and_sign(nonce, box, signing_key)
    print(len(message))
    print("Sending challenge to client")
    conn.send(message)

    # response
    message = conn.recv(Box.NONCE_SIZE + SIGNATURE_SIZE)
    print("Received response from client")
    signed_message, decrypted_nonce = get_signature_and_message(message)

    verify_key.verify(signed_message)
    if nonce == decrypted_nonce:
        print(f"Client {client_user} authenticated successfully")
    else:
        print(f"Failed login from client {client_user}")
        conn.close()

    # session key
    session_key = random(SESSION_KEY_SIZE)
    signed_message = encrypt_and_sign(session_key, box, signing_key)
    conn.send(signed_message)

    s.shutdown(1)
    s.close()


if __name__ == "__main__":
    main()
