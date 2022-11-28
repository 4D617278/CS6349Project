#!/usr/bin/env python3
from enum import IntEnum
from nacl.public import Box 
from nacl.utils import random
import socket
from sys import argv

MIN_PORT = 0
MAX_PORT = 65535

class Args(IntEnum):
    host = 1
    port = 2
    keys = 3

def main():
    if len(argv) < 2: 
        print(f'usage: {argv[0]} <host> <port> <keys>')
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
        keys = f.read().split()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((argv[Args.host], port))

    nonce = s.recv(Box.NONCE_SIZE)
    print(nonce)

if __name__ == '__main__':
    main()
