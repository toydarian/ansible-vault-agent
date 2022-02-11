#!/usr/bin/env python3
import argparse
import configparser
import logging
import socket
import sys
from getpass import getpass
from pathlib import Path, PosixPath

SOCKET_NOT_FOUND = 2
AGENT_ISSUE = 3
DEFAULT_SOCKET_PATH = f"{str(Path.home())}/.vault-agent.sock"
CONFIG_LOCATION = "./vault-agent-client.ini"

fmt = logging.Formatter("[%(levelname)s] %(message)s")
logger = logging.getLogger("vault-agent")
logger.setLevel(logging.DEBUG)
stream_handler = logging.StreamHandler(sys.stderr)
stream_handler.setFormatter(fmt)
logger.addHandler(stream_handler)


def create_connection(socket_path: PosixPath) -> socket.socket:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(str(socket_path))
    return s


def is_socket(socket_path: str) -> None:
    if not Path.is_socket(PosixPath(socket_path).expanduser()):
        logger.error(f"'{socket_path}' is not a socket or doesn't exist!")
        sys.exit(SOCKET_NOT_FOUND)


def get_secret(arguments: argparse.Namespace) -> None:
    get_secret_ansible(arguments.socket, arguments.vault_id)


def get_secret_ansible(socket_path: str, vault_id: str) -> None:
    s = create_connection(PosixPath(socket_path).expanduser())
    s.send(b"GET " + vault_id.encode("utf-8"))
    answer = s.recv(4096).decode("utf-8")
    tokens = answer.split()
    if tokens[0] == "HIT":
        logger.debug("Secret found")
        print(tokens[1])
    else:
        logger.error(f"No secret for vault-id '{vault_id}' found.")
        s.close()
        sys.exit(AGENT_ISSUE)
    s.close()


def put_secret(arguments: argparse.Namespace) -> None:
    secret = getpass(prompt="Enter the secret: ")
    s = create_connection(PosixPath(arguments.socket).expanduser())
    s.send(b"PUT " + f"{arguments.vault_id} {secret}".encode("utf-8"))
    answer = s.recv(4096)
    if answer == b"STORED":
        logger.info("Secret stored in agent.")
    elif answer == b"EXISTS":
        logger.error("A secret already exists for that ID in the agent. Not updated.")
        s.close()
        sys.exit(AGENT_ISSUE)
    else:
        logger.error("Could not store secret. Reason unknown.")
        s.close()
        sys.exit(AGENT_ISSUE)
    s.close()


def replace_secret(arguments: argparse.Namespace) -> None:
    secret = getpass(prompt="Enter the secret: ")
    s = create_connection(PosixPath(arguments.socket).expanduser())
    s.send(b"REPLACE " + f"{arguments.vault_id} {secret}".encode("utf-8"))
    answer = s.recv(4096)
    if answer == b"STORED":
        logger.info("Secret stored (or replaced) in agent.")
    else:
        logger.error("Could not store secret. Reason unknown.")
        s.close()
        sys.exit(AGENT_ISSUE)
    s.close()


def stop_agent(arguments: argparse.Namespace) -> None:
    logger.debug("Asking agent to stop.")
    s = create_connection(PosixPath(arguments.socket).expanduser())
    s.send(b"EXIT")
    s.close()


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == "--vault-id":
        # for calls from ansible
        stream_handler.setLevel(logging.ERROR)
        s_path = DEFAULT_SOCKET_PATH
        if Path.is_file(PosixPath(CONFIG_LOCATION)):
            cp = configparser.ConfigParser()
            cp.read(CONFIG_LOCATION)
            s_path = cp['DEFAULT']['socket']
        is_socket(s_path)
        get_secret_ansible(s_path, sys.argv[2])

    else:
        # for using from the commandline
        parser = argparse.ArgumentParser(description="Client for the vault-agent.")
        parser.add_argument("--socket", "-s",
                            default=DEFAULT_SOCKET_PATH,
                            help="Path to the unix-socket that is used for communication.")
        parser.add_argument("--verbose", "-v",
                            action="store_true",
                            help="Be verbose. Sets logger to 'DEBUG', secrets will NEVER be logged.")
        command = parser.add_subparsers(help="Action to perform.")
        get = command.add_parser("get", help="Get a secret from the agent.")
        get.add_argument("--vault-id", "-i", required=True, help="The ID of the secret to retrieve.")
        get.set_defaults(func=get_secret)
        put = command.add_parser("put", help="Put a secret into the agent.")
        put.add_argument("--vault-id", "-i", required=True, help="The ID of the secret to retrieve.")
        put.set_defaults(func=put_secret)
        replace = command.add_parser("replace", help="Add or replace a secret in the agent.")
        replace.add_argument("--vault-id", "-i", required=True, help="The ID of the secret to retrieve.")
        replace.set_defaults(func=replace_secret)
        exit_cmd = command.add_parser("exit", help="Tell the agent to exit and forget all secrets.")
        exit_cmd.set_defaults(func=stop_agent)

        args = parser.parse_args()
        if args.verbose:
            stream_handler.setLevel(logging.DEBUG)
        else:
            stream_handler.setLevel(logging.INFO)

        is_socket(args.socket)
        args.func(args)
