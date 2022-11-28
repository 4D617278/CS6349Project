#!/usr/bin/env python3
import socket
from sys import argv

HOST = '0.0.0.0'
MIN_PORT = 1024
MAX_PORT = 65535

def main():
    if len(argv) < 2: 
        print(f'usage: {argv[0]} <port>')
        exit(1)

    try:
        port = int(argv[1])
    except ValueError:
        print('port is not integer')
        exit(1)

    if port < MIN_PORT or MAX_PORT < port:
        print('MIN_PORT <= port <= MAX_PORT')
        exit(1)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, port))
    s.listen()
    s.accept()


if __name__ == '__main__':
    main()
