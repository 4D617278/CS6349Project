#!/usr/bin/env python3
import argparse
import socket
import threading
from time import sleep
from nacl.encoding import HexEncoder 
from nacl.hash import sha256 
from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey

from config import CLIENT_PORT, HOST, METADATA_SIZE, SESSION_KEY_SIZE, SIGNATURE_SIZE, MAX_DATA_SIZE
from utility import client_port, mac_send, recv_decrypt, server_port, sign_send

class Client:
    def __init__(self, user, port):
        self.user = user
        # key used to decrypt messages
        self.private_key = PrivateKey(
            open(f"./key_pairs/{user}", encoding="utf-8").read(), HexEncoder
        )
        # key used to sign messages
        self.signing_key = SigningKey(
            open(f"./key_pairs/{user}_dsa", encoding="utf-8").read(), HexEncoder
        )
        # key used to encrypt messages for the server
        self.server_public_key = PublicKey(
            open("./key_pairs/server.pub", encoding="utf-8").read(), HexEncoder
        )
        # key used to verify messages from the server
        self.verify_key = VerifyKey(
            open("./key_pairs/server_dsa.pub", encoding="utf-8").read(), HexEncoder
        )
        self.keys = {}
        self.peer = None
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((HOST, port))

    def start(self, host, port):
        args = (host, port)
        threading.Thread(target=self.chat).start()
        threading.Thread(target=self.connect_server, args=args).start()

    def chat(self):
        self.s.listen()

        while True:
            conn, addr = self.s.accept()

            if addr[0] != self.peer:
                conn.close()
                continue

            msg = conn.recv(MAX_DATA_SIZE)

            conn.close()

    def connect_server(self, host, port):
        box = Box(self.private_key, self.server_public_key)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))

        s.send(bytes(self.user, "utf-8"))

        # challenge
        print("Received challenge from server")
        decrypted_nonce = recv_decrypt(s, box, self.verify_key)

        # response
        sign_send(s, decrypted_nonce, self.signing_key)

        # select user
        client_list = recv_decrypt(s, box, self.verify_key)
        if not client_list:
            print("Unsuccessful authentication to server")
            return
        print("Successfully authenticated to server")

        name_ips = client_list.decode().split('\n')
        name_to_ip = {}

        for name_ip in name_ips:
            name, ip = name_ip.split(':')
            name_to_ip[name] = ip

        names = '\n'.join(name_to_ip.keys())
        print(f"List of available clients: {names}")

        name = ""
        while name not in name_to_ip:
            name = input("Name: ")
        
        name = bytes(name, 'utf-8')
        mac_send(s, name, box, self.signing_key)

        # session key
        session_key = recv_decrypt(s, box, self.verify_key)
        self.peer = name_to_ip[name]
        self.keys[address] = session_key

    def die(self):
        self.s.shutdown(1)
        self.s.close()

def main():
    parser = argparse.ArgumentParser("Client application")
    parser.add_argument("--host", default="localhost", help="Location of server")
    parser.add_argument(
        "--server_port",
        type=server_port,
        default=8000,
        help="Port that server is running on",
    )
    parser.add_argument(
        "--client_port",
        type=client_port,
        default=32768,
        help="Port that client is running on",
    )
    parser.add_argument("user", help="Name of the user logging in")
    args = parser.parse_args()

    c = Client(args.user, args.client_port)
    c.start(args.host, args.server_port)
    c.die()

if __name__ == "__main__":
    main()
