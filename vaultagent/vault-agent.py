#!/usr/bin/env python3
import argparse
import logging
import os
import signal
import socket
import sys
from pathlib import Path, PosixPath

fmt = logging.Formatter("%(asctime)s [%(levelname)s] : %(message)s")
logger = logging.getLogger("vault-agent")
logger.setLevel(logging.DEBUG)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(fmt)
logger.addHandler(stream_handler)

g_socket_path = ""
SOCKET_PATH_ERROR = 2


def handle_sigint(sig, frame) -> None:
    logger.info("Received SIG-INT. Sending 'EXIT' to myself.")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(g_socket_path)
    s.send(b"EXIT")
    s.close()


def serve_key_agent(socket_path: PosixPath) -> None:

    vault_passes = {}

    if Path.is_socket(socket_path):
        logger.info(f"Socket '{socket_path}' already exists. Removing it")
        os.remove(socket_path)
    elif Path.exists(Path(socket_path)):
        logger.error(f"Path '{socket_path}' already exists, but is not a socket!")
        sys.exit(SOCKET_PATH_ERROR)

    logger.debug(f"Binding on '{socket_path}'")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    server.listen()
    os.chmod(socket_path, 0o700)

    logger.info("Ready to receive connections")
    while True:
        conn, _ = server.accept()
        # TODO handle longer messages
        dg = conn.recv(4096)
        tokens = dg.split()
        if tokens[0] == b"GET":
            vault_id = tokens[1]
            logger.debug(f"Received GET for '{vault_id.decode('utf-8')}'")
            if vault_id in vault_passes:
                logger.debug("Found ID, sending response")
                conn.send(b"HIT " + vault_passes[vault_id])
            else:
                logger.debug("ID unknown")
                conn.send(b"MISS")
        elif tokens[0] == b"PUT":
            vault_id = tokens[1]
            secret = tokens[2]
            logger.debug(f"Received PUT for '{vault_id.decode('utf-8')}'")
            if vault_id in vault_passes:
                logger.debug("Vault ID exists, not storing")
                conn.send(b"EXISTS")
            else:
                logger.debug("Storing secret")
                vault_passes[vault_id] = secret
                conn.send(b"STORED")
        elif tokens[0] == b"REPLACE":
            vault_id = tokens[1]
            secret = tokens[2]
            logger.debug(f"Received REPLACE for '{vault_id.decode('utf-8')}'. "
                         "Storing it without checking for existing secret.")
            vault_passes[vault_id] = secret
            conn.send(b"STORED")
        elif tokens[0] == b"EXIT":
            logger.info("Received 'EXIT'")
            conn.close()
            break
        else:
            logger.info(f"Received unknown method '{dg.decode('utf-8')}'")
            conn.send(b"UNKNOWN_METHOD")
        conn.close()

    socket.close(server.fileno())
    if Path.is_socket(socket_path):
        logger.info(f"Cleaning up socket '{socket_path}'")
        os.remove(socket_path)
    logger.info("Bye-bye")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Simple key-agent for ansible-vault.")
    parser.add_argument("--socket", "-s",
                        default=f"{str(Path.home())}/.vault-agent.sock",
                        help="Path to the unix-socket that is used for communication.")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Be verbose. Sets logger to 'DEBUG', secrets will NEVER be logged.")
    args = parser.parse_args()
    if args.verbose:
        stream_handler.setLevel(logging.DEBUG)
    else:
        stream_handler.setLevel(logging.INFO)

    signal.signal(signal.SIGINT, handle_sigint)
    sp = PosixPath(args.socket).expanduser()
    g_socket_path = str(sp)  # make it global, so we can send a msg when we get sig-int
    serve_key_agent(sp)
