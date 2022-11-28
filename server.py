#!/usr/bin/env python3
from enum import IntEnum
from nacl.public import Box 
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

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, port))
    s.listen()
    conn, addr = s.accept()

    # 24 bytes
    nonce = random(Box.NONCE_SIZE)

    # challenge
    conn.send(nonce)
    enc = conn.recv(64)
    print(f'len: {len(enc)}')
    print(f'enc: {enc}')

if __name__ == '__main__':
    main()
