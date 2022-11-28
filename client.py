#!/usr/bin/env python3
from constants import BYTEORDER, MAX_ID_LEN, NUM_SERVERS, SERVER_ID
from enum import IntEnum
from nacl.encoding import HexEncoder
from nacl.public import Box, PrivateKey, PublicKey
from nacl.utils import random
import socket
from sys import argv

MIN_PORT = 0
MAX_PORT = 65535

class Args(IntEnum):
    host = 1
    port = 2
    keys = 3
    id = 4

def main():
    if len(argv) < len(Args) + 1:
        args = ' '.join(f'<{a.name}>' for a in Args)
        print(f'usage: {argv[0]} {args}')
        exit(1)

    try:
        port = int(argv[Args.port])
        id = int(argv[Args.id])
    except ValueError:
        print('port or id is not integer')
        exit(1)

    if port < MIN_PORT or MAX_PORT < port:
        print(f'{MIN_PORT} <= port <= {MAX_PORT}')
        exit(1)

    keys = None
    with open(argv[Args.keys], 'r') as f:
        keys = f.read().split()

    if id < NUM_SERVERS or id >= len(keys):
        print('id is invalid')
        exit(1)

    sk = PrivateKey(keys[id], HexEncoder)
    pk = PublicKey(keys[SERVER_ID], HexEncoder)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((argv[Args.host], port))

    s.send(id.to_bytes(MAX_ID_LEN, BYTEORDER))

    nonce = s.recv(Box.NONCE_SIZE)
    box = Box(sk, pk)
    enc = box.encrypt(nonce)
    s.send(enc)

if __name__ == '__main__':
    main()
