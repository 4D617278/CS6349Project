#!/usr/bin/env python3
from constants import BYTEORDER, MAX_ID_LEN, NUM_SERVERS, SERVER_ID
from enum import IntEnum
from nacl.encoding import HexEncoder
from nacl.public import Box, PrivateKey, PublicKey
from nacl.utils import random
import socket
from sys import argv

HOST = '0.0.0.0'
MIN_PORT = 1024
MAX_PORT = 65535

class Args(IntEnum):
    port = 1
    keys = 2

def main():
    if len(argv) < len(Args) + 1: 
        args = ' '.join(f'<{a.name}>' for a in Args)
        print(f'usage: {argv[0]} {args}')
        exit(1)

    try:
        port = int(argv[Args.port])
    except ValueError:
        print('port is not integer')
        exit(1)

    if port < MIN_PORT or MAX_PORT < port:
        print(f'{MIN_PORT} <= port <= {MAX_PORT}')
        exit(1)

    keys = None
    with open(argv[Args.keys], 'r') as f:
        keys = f.read().splitlines()

    pkeys = [None] * NUM_SERVERS
    for i in range(NUM_SERVERS):
        pkeys[i] = PublicKey(keys[i], HexEncoder)

    skeys = [None] * (len(keys) - NUM_SERVERS + 1)
    for i in range(NUM_SERVERS, len(keys)):
        skeys[i] = PrivateKey(keys[i], HexEncoder)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, port))
    s.listen()
    conn, addr = s.accept()

    client_id_bytes = conn.recv(MAX_ID_LEN)
    client_id = int.from_bytes(client_id_bytes, BYTEORDER)

    # 24 bytes
    nonce = random(Box.NONCE_SIZE)

    # challenge
    conn.send(nonce)
    enc = conn.recv(64)

    box = Box(skeys[client_id], pkeys[SERVER_ID])
    dec = box.decrypt(enc)

    print(f'dec: {dec}, nonce: {nonce}')

if __name__ == '__main__':
    main()
