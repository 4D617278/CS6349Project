#!/usr/bin/env python3
import argparse
import socket
import threading
from time import sleep
from nacl.encoding import HexEncoder 
from nacl.hash import sha256 
from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey

from config import HOST, MAX_PORT
from utility import port, mac_send, recv_dec, sign_send

class Client:
    def __init__(self, user):
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
        self.box = Box(self.private_key, self.server_public_key)
        self.clients = {}
        self.peer = None
        self.server = None

    def start(self, host, port):
        args = (host, port)
        threading.Thread(target=self.shell).start()
        threading.Thread(target=self.login, args=args).start()

    def shell(self):
        while True:
            cmd = input("> ")

            match cmd:
                case "c":
                   self.chat()  
                case "g":
                   self.get_clients()  
                case "q":
                    break
                case _:
                    print("Commands: ")

        self.die()

    def chat(self):
        user = input("Username: ")

        if user not in self.clients:
            print('No user {user}')
            return

        ip, port, key = self.clients[user]

        if not key:
            key = self.get_key(user)

        print(f'Key: {key}')

        self.peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.peer.connect((ip, int(port)))
        except ConnectionRefusedError:
            print(f'{user} is busy')
            return

        msg = input("> ")
        mac_send(self.peer, bytes(msg, "utf-8"), key)


    def login(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.connect((host, port))
        self.server.send(bytes(self.user, "utf-8"))

        # challenge
        print("Received challenge from server")
        decrypted_nonce = recv_dec(self.server, self.verify_key, self.box)

        # response
        sign_send(self.server, decrypted_nonce, self.signing_key)

        # server sym key
        self.sym_key = recv_dec(self.server, self.verify_key, self.box)

        self.get_clients()
        threading.Thread(target=self.get_keys).start()

    def get_keys(self):
        while True:
            msg = recv_dec(self.server, self.sym_key)

            if not msg:
                continue

            user, key = msg.decode().split(':')

            if user in self.clients:
                self.clients[user][2] = key
                print(f'Key: {key}')

    def get_clients(self):
        mac_send(self.server, b'g', self.sym_key)
        client_list = recv_dec(self.server, self.sym_key)

        if not client_list:
            print("Not logged in")
            return

        clients = client_list.decode().split('\n')
        print(clients)

        for client in clients:
            name, ip, port = client.split(':')
            self.clients[name] = [ip, port, None]

    def get_key(self, user):
        mac_send(self.server, bytes(user, "utf-8"), self.sym_key)
        key = recv_dec(self.server, self.sym_key)

        if not key:
            print("Not logged in")
            return

        self.clients[user][2] = key

        return key

    def die(self):
        self.server.shutdown(1)
        self.server.close()

def main():
    parser = argparse.ArgumentParser("Client application")
    parser.add_argument("--host", default="localhost", help="Location of server")
    parser.add_argument(
        "--port",
        type=port,
        default=8000,
        help="Port that server is running on",
    )
    parser.add_argument("user", help="Name of the user logging in")
    args = parser.parse_args()

    c = Client(args.user)
    c.start(args.host, args.port)

if __name__ == "__main__":
    main()
