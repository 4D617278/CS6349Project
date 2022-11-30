#!/usr/bin/env python3
from constants import NUM_SERVERS
from enum import IntEnum
from nacl.encoding import HexEncoder
from nacl.public import PrivateKey, PublicKey
from sys import argv

class Args(IntEnum):
    numClients = 1
    path = 2

def make_sk(numClients):
    hex_keys = [None] * (NUM_SERVERS + numClients)

    for i in range(NUM_SERVERS):
        sk = PrivateKey.generate()
        hex_keys[i] = sk.public_key.encode(HexEncoder)

    for i in range(NUM_SERVERS, len(hex_keys)):
        sk = PrivateKey.generate()
        hex_keys[i] = sk.encode(HexEncoder)
    
    return hex_keys

def main():
    if len(argv) < len(Args) + 1: 
        args = ' '.join(f'<{a.name}>' for a in Args)
        print(f'usage: {argv[0]} {args}')
        exit(1)

    try:
        numClients = int(argv[Args.numClients])
    except ValueError:
        print('number of clients is not integer')
        exit(1)

    if numClients <= 0:
        print('number of clients is not positive')
        exit(1)

    hex_keys = make_sk(numClients)

    with open(argv[Args.path], 'wb+') as f:
        f.write(b'\n'.join(hex_keys))

if __name__ == '__main__':
    main()
