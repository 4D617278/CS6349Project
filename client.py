#!/usr/bin/env python3
import argparse
import socket
import threading
from time import sleep
from nacl.encoding import HexEncoder 
from nacl.hash import sha256 
from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey

from config import HOST
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
        self.auth = 0
        self.box = Box(self.private_key, self.server_public_key)
        self.clients = {}
        self.peer = None
        self.server = None

        self.msgs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.msgs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.msgs.bind((HOST, port))

    def start(self, host, port):
        args = (host, port)
        threading.Thread(target=self.shell).start()
        threading.Thread(target=self.login, args=args).start()

    def shell(self):
        cmd = ""

        while cmd != "q":
            cmd = input("> ")

            match cmd:
                case "g":
                   self.get_clients()  
                case _:
                    print("Commands: g")

        self.die()

    def get_msg():
        self.msgs.listen()

        while True:
            conn, addr = self.msgs.accept()

            if addr[0] != self.peer:
                conn.close()
                continue

            # msg = conn.recv_decrypt(self.msgs, )

            conn.close()

    def login(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.connect((host, port))

        self.server.send(bytes(self.user, "utf-8"))

        # challenge
        print("Received challenge from server")
        decrypted_nonce = recv_decrypt(self.server, self.box, self.verify_key)

        # response
        sign_send(self.server, decrypted_nonce, self.signing_key)

        self.get_clients()

    def get_clients(self):
        mac_send(self.server, b'g', self.box, self.signing_key)
        client_list = recv_decrypt(self.server, self.box, self.verify_key)

        if not client_list:
            self.auth = 0
            print("Not logged in")
            return

        self.auth = 1

        clients = client_list.decode().split('\n')

        for client in clients:
            name, ip, port, key = client.split(':')
            self.clients[name] = (ip, port, key)

    def die(self):
        self.msgs.shutdown(1)
        self.msgs.close()
        self.server.shutdown(1)
        self.server.close()

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

if __name__ == "__main__":
    main()
