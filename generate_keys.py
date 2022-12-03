#!/usr/bin/env python3
import argparse

from nacl.encoding import HexEncoder
from nacl.public import PrivateKey
from nacl.signing import SigningKey


def create_key(username):
    private_key = PrivateKey.generate()
    encoded_private_key = private_key.encode(HexEncoder)
    with open(f"./key_pairs/{username}", "wb") as f:
        f.write(encoded_private_key)

    public_key = private_key.public_key
    encoded_public_key = public_key.encode(HexEncoder)
    with open(f"./key_pairs/{username}.pub", "wb") as f:
        f.write(encoded_public_key)

    signing_key = SigningKey.generate()
    encoded_signing_key = signing_key.encode(HexEncoder)
    with open(f"./key_pairs/{username}_dsa", "wb") as f:
        f.write(encoded_signing_key)

    verify_key = signing_key.verify_key
    encoded_verify_key = verify_key.encode(HexEncoder)
    with open(f"./key_pairs/{username}_dsa.pub", "wb") as f:
        f.write(encoded_verify_key)

def main():
    parser = argparse.ArgumentParser("Generate keys for client and server")
    parser.add_argument("users", nargs="+", help="List of users to create keys for")
    parser.add_argument("--create-server", action="store_true", help="Create key for server")
    args = parser.parse_args()

    if args.create_server:
        create_key("server")

    for user in args.users:
        create_key(user)

if __name__ == '__main__':
    main()
