# SSH CA
A **very** simple SSH CA service with **only** 150 lines of Python code.

## Why
OpenSSH user certificate is a better authentication solution than the traditional public key.
But there is a small problem: how to sign SSH keys for many users?

We have hundreds of Linux nodes and different roles (deploy/dev/ops) for many users. For example, the deploy/dev roles can ssh to a specific node, but the ops role can ssh to all the nodes.

It's difficult to get those things done without an automatic solution.

## How
The idea is **very** simple:
1. To sign a key for a user, we MUST have his SSH public key.
2. If we have his SSH public key, we can authenticate him by that key.

So, the solution is straightforward:
1. User uses ssh to connect to the SSH CA service 
2. The SSH CA service authenticates him by his public key, signs the key, and returns the signed key to him.

## Usage
There are a CA admin and many SSH users.

### SSH User
Every SSH user must:
1. choose him username, "user1" for example.
2. generate his SSH key pair: `ssh-keygen -t ed25519`
3. send his public file to CA admin, filename is user1.pub.

### SSH Admin
Create /etc/sshca/ with the following files/dirs:
1. ca: The CA private key file.
2. ssh-host-key: Host key for CA's SSH service.
3. config.json: as the example.
4. users/: contains users's SSH public keys
5. users/user1.pub: user1's public SSH key

Then starts the SSH CA service by  `python3 main.py` which will listen on port 65022.

### Request a signed key
`ssh ssh://user1@ca.ssh.service:65022 ops`

Then copy the returned key to ~/.ssh/id_ed25519-cert.pub. 

or:

`scp scp://user1@ca.ssh.service:65022/ops.pub .`

If 'enable_scp' is true in config.json.

## TODO
1. read-only sftp/scp
2. cert cache

