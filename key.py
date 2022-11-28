#!/usr/bin/env python3
from nacl.encoding import HexEncoder
from nacl.public import PrivateKey
from sys import argv

def main():
    if len(argv) < 3: 
        print(f'usage: {argv[0]} <numClients> <path>')
        exit(1)

    try:
        numClients = int(argv[1])
    except ValueError:
        print('number of clients is not integer')
        exit(1)

    if numClients <= 0:
        print('number of clients is not positive')
        exit(1)

    hex_keys = [None] * numClients

    for i in range(numClients):
        sk = PrivateKey.generate()
        hex_keys[i] = sk.encode(HexEncoder)

    with open(argv[2], 'wb+') as f:
        f.write(b'\n'.join(hex_keys))

if __name__ == '__main__':
    main()
