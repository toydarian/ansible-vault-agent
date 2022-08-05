Vault Agent
===========

This is a simple, ssh-key-agent like agent for ansible-vault passwords and your become-password.  
It consists of two components, a server and a client-script.  
The server will listen on a unix-socket and store tuples of vault-ids and secrets. It will serve those when requested.  
The client can connect to the socket and send commands to store or retrieve secrets.

This is pure python and neither client nor server have any dependencies except standard-components, so you should be 
able to get this to run on any linux-machine where ansible works, even if you don't have sudo.  
Only Python 3 is supported, though, and it is only tested on Linux. It should work on MacOS (not tested) and might work 
on the WSL on Windows (not tested, as well).

How To
------

The whole thing works without configuration.  
Start the server by running `vault-agent.py` and then add a secret by running 
`vault-agent-client.py put --vault-id <your-vault-id>`. It will ask you for the secret.  
You can then run `vault-agent-client.py get --vault-id <your-vault-id>` to retrieve the secret.  
To use it in an ansible command, append `--vault-id <your-vault-id>@/path/to/vault-agent-client.py` to use the agent for
vault-secrets and `--become-password-file /path/to/vault-agent-client.py` to use it for your become-password.  

You can also use `--vault-pass-file /path/to/vault-agent-client.py`. In that case, ansible will ask for vault-id 
`default`. So you need to use `default` as vault-id when adding the passphrase.

Take a look at the [ansible docs](https://docs.ansible.com/ansible/latest/reference_appendices/config.html) for more 
options to configure these globally or per-project.

Options
-------

These options are common for client and server.  
You can use `-v` to enable debug-output (we won't log secrets, though).  
Use `-s </path/to/socket>` to specify a socket. You can use `~` in the beginning to refer to your home-directory.    
The `-v` and `-s` options work on the client, as well as the server. They need to be provided before the sub-command.

### Client

The client has five sub-commands:

 - `get` to get a secret from the server (requires `--vault-id`)
 - `put` to put a secret on the server, which will fail if the vault-id is already there (requires `--vault-id`)
 - `replace` to put a secret on the server or replace it if there is already one with this vault-id (requires `--vault-id`)
 - `exit` to ask the server to stop and clean up the socket
 - `become` for commands to store/retrieve the become-password, which has two sub-commands
   - `get` to retrieve the become-password
   - `put` to store the become-password which will also replace a previously stored password

All `put` and `replace` will ask for the secret to put on the server on `stdin`.  
The client prints all messages to `stderr` to be compatible with ansible.

If you don't use the default socket, put an ini-file called `vault-agent-client.ini` in the directory where you run your
ansible command, that contains the lines below, otherwise the client will not be able to find the socket and will fail.  
When in doubt, just use the default socket.

_vault-agent-client.ini:_
```text
[DEFAULT]
socket = /path/to/socket
```

### Server

The server doesn't know any options except the ones mentioned earlier. You can send `SIGINT` 
(e.g. by pressing `Ctrl + C` in the terminal) to the server. It will then "forget" all secrets, clean up the socket and 
exit.

The server doesn't load any configuration file.

Additional Notes
----------------

### Q&A:

 - **Q:** Are the secrets stored encrypted in RAM?  
   **A:** No - if somebody can read your RAM, you are f****d already.
 - **Q:** Couldn't anybody on the machine read from the socket?  
   **A:** No, only the user who started the server is allowed to access the socket. (`root` can access it, as well)
 - **Q:** Speaking of sockets - is the port open on the network?  
   **A:** No! This is a unix-file-socket. No network-communication is involved.

### Future Features

 - Make the server forget a secret without shutting it down
 - Daemonize the server
 - `setup.py` or other way to build a wheel
