#!/usr/bin/env python3
import argparse
import socket
import sys
from threading import Thread
from time import sleep

from nacl.encoding import HexEncoder
from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey

from config import HOST, MAX_PORT, MIN_PORT
from utility import mac_send, port, recv_dec, sign_send


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
        self.clients = {}
        self.peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.peer_name = ""
        self.peer_key = None
        self.server = None
        self.running_shell = True

    def start(self, host, port):
        args = (host, port)
        Thread(target=self.shell).start()
        Thread(target=self.login, args=args).start()

    def shell(self):
        sleep(0.25)
        print("Commands: c, g, p, q")
        while self.running_shell:
            cmd = input("> ")
            if not self.running_shell:
                sys.stdout.flush()
                break

            match cmd:
                case "c":
                    self.chat(self.peer, self.peer_name, self.peer_key)
                case "g":
                    self.get_clients()
                case "p":
                    self.peer_connect()
                case "q":
                    self.running_shell = False
                case _:
                    print("unknown command")
                    print("Commands: c, g, p, q")

        # self.die()
        return

    def peer_connect(self):
        user = input("Username: ")

        if user not in self.clients:
            print(f"No user {user}")
            return

        self.peer_name = user

        ip = self.clients[user][0]
        key, port = self.get_key(user)

        if not key or not port:
            print(f"{user} is busy")
            return

        self.peer.close()
        self.peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.peer_key = key

        try:
            self.peer.connect((ip, int(port)))
        except ConnectionRefusedError:
            print(f"{user} is busy")
            return

        print(f"You are connected to user {user} on port {port}")
        self.chat(self.peer, self.peer_name, self.sym_key)

    def chat(self, peer, user, key):
        try:
            peer.getpeername()
        except OSError:
            print("No peer is set")
            return

        args = (peer, user, key)
        Thread(target=self.recv_msgs, args=args).start()
        self.send_msgs(peer, user, key)

    def recv_msgs(self, sock, user, key):
        while True:
            try:
                msg = recv_dec(sock, key)
            except OSError:
                break

            if not msg:
                break

            print(f"{user}: {msg.decode()}")

    def send_msgs(self, sock, user, key):
        while True:
            msg = input(f"{self.user}: ")

            if not msg:
                break

            try:
                mac_send(sock, bytes(msg, "utf-8"), key)
            except BrokenPipeError:
                break

        sock.close()

    def login(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.connect((host, port))
        port = (self.server.getsockname()[1] + 1) % MAX_PORT
        Thread(target=self.get_keys, args=(port,)).start()

        self.server.send(bytes(self.user, "utf-8"))

        # challenge
        box = Box(self.private_key, self.server_public_key)
        decrypted_nonce = recv_dec(self.server, self.verify_key, box)

        # response
        sign_send(self.server, decrypted_nonce, self.signing_key)

        # server sym key
        self.sym_key = recv_dec(self.server, self.verify_key, box)

        self.get_clients()

    def get_keys(self, port):
        self.keySock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.keySock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.keySock.bind((HOST, port))
        self.keySock.listen()

        while True:
            conn, addr = self.keySock.accept()

            msg = recv_dec(conn, self.sym_key)

            if not msg:
                continue

            print(f"Msg: {msg}")
            self.running_shell = False

            user, key = msg.decode().split(":", 1)

            if user in self.clients:
                self.clients[user][2] = key

            ans = input(f"Chat with {user}? ")

            if ans != "y":
                mac_send(conn, b"0", self.sym_key)
                continue

            self.peer.close()
            self.peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.peer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.peer_key = bytes(key, "utf-8")
            self.peer_name = user

            for port in range(MIN_PORT, MAX_PORT + 1):
                try:
                    self.peer.bind((HOST, port))
                    break
                except OSError:
                    continue

            print(f"Listening on port {port}")

            self.peer.listen()
            msg = bytes(str(port), "utf-8")
            mac_send(conn, msg, self.sym_key)
            print(f"Waiting for connection from {user} now")
            self.peer, addr = self.peer.accept()
            print(f"peer {user} connected")
            print(addr)
            self.chat(self.peer, self.peer_name, self.sym_key)

    def getpeername(self):
        return self.peer_name

    def get_clients(self):
        mac_send(self.server, b"g", self.sym_key)
        client_list = recv_dec(self.server, self.sym_key)

        if not client_list:
            print("Not logged in")
            return

        clients = client_list.decode().split("\n")

        for client in clients:
            name, ip, port = client.split(":")

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
            return key, port

        self.clients[user][2] = key
        port = port.decode()

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
