#!/usr/bin/env python3
import argparse
import socket
import threading
from time import sleep
from nacl.encoding import HexEncoder 
from nacl.hash import sha256 
from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey

from config import HOST, MAX_PORT, MIN_PORT
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

        ip = self.clients[user][0]
        key, port = self.get_key(user)

        print(f'Key: {key}')

        self.peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        print(f'IP: {ip}, Port: {port}')

        try:
            self.peer.connect((ip, int(port)))
        except ConnectionRefusedError:
            print(f'{user} is busy')
            return

        while True:
            msg = input(f"{user}> ")

            if not msg:
                break

            mac_send(self.peer, bytes(msg, "utf-8"), key)

        self.peer.close()

    def login(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.connect((host, port))
        threading.Thread(target=self.get_keys).start()

        self.server.send(bytes(self.user, "utf-8"))

        # challenge
        print("Received challenge from server")
        decrypted_nonce = recv_dec(self.server, self.verify_key, self.box)

        # response
        sign_send(self.server, decrypted_nonce, self.signing_key)

        # server sym key
        self.sym_key = recv_dec(self.server, self.verify_key, self.box)

        self.get_clients()

    def get_keys(self):
        self.keySock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.keySock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        port = (self.server.getsockname()[1] + 1) % MAX_PORT
        self.keySock.bind((HOST, port))
        self.keySock.listen()

        while True:
            conn, addr = self.keySock.accept()

            msg = recv_dec(conn, self.sym_key)

            if not msg:
                continue

            print(f'Msg: {msg}')

            user, key = msg.decode().split(':', 1)

            if user in self.clients:
                self.clients[user][2] = key
                print(f'Key: {key}')

            self.peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            for port in range(MIN_PORT, MAX_PORT + 1):
                try:
                    self.peer.bind((HOST, port))
                    print(f'Port: {port}')
                    break
                except OSError:
                    continue

            self.peer.listen()

            msg = bytes(str(port), "utf-8")
            mac_send(conn, msg, self.sym_key)
            peer_conn, addr = self.peer.accept()

            while msg:
                msg = recv_dec(peer_conn, self.sym_key)
                print(f'Msg: {msg}')

    def get_clients(self):
        mac_send(self.server, b'g', self.sym_key)
        client_list = recv_dec(self.server, self.sym_key)

        if not client_list:
            print("Not logged in")
            return

        clients = client_list.decode().split('\n')

        for client in clients:
            name, ip, port = client.split(':')

            if name in self.clients:
                self.clients[name][0] = ip
                self.clients[name][1] = port
            else:
                self.clients[name] = [ip, port, None]

        print(self.clients)

    def get_key(self, user):
        mac_send(self.server, bytes(user, "utf-8"), self.sym_key)
        port = recv_dec(self.server, self.sym_key)
        key = recv_dec(self.server, self.sym_key)

        if not key or not port:
            print("Not logged in")
            return

        self.clients[user][2] = key
        port = port.decode()

        print(f'Port: {port}')

        return key, port

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
