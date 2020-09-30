#!/usr/bin/env python3
#coding: utf-8

import os
import sys
import json
import time
import getpass
import asyncio 
import logging

import asyncssh

ca = None
config = None

# Default cert permissions
permissions = {
    'permit_x11_forwarding': False,
    'permit_agent_forwarding': False,
    'permit_port_forwarding': False,
}


def get_user_pubkey(username):
    """username -> keypath"""
    return os.path.join(config['user_key_path'], '%s.pub' % username)


def load_ca(path):
    """Load CA private key"""
    password = getpass.getpass(prompt='Input the CA password: ')
    cert = asyncssh.read_private_key(path, passphrase=password)
    return cert


def generate_user_cert(role, hostname, username, cfg):
    """Generate a Signed user cert"""
    user_key = asyncssh.read_public_key(get_user_pubkey(username))

    if cfg.get('require_host', True):
        principal = '%s@%s' % (role, hostname)
        comment = '%s-%s@%s' % (role, username, hostname)
    else:
        principal = role
        comment = '%s-%s' % (role, username)

    valid_before = cfg.get('valid_before', '2h')

    cert = ca.generate_user_certificate(user_key, username,
            principals=[principal], valid_before=valid_before,
            serial=int(time.time()), comment=comment, **permissions)
    return cert


def handle_client(process):
    """Handle client"""
    stdout, stderr, logger, command = process.stdout, process.stderr, process.logger, process.command
    username = process.get_extra_info('username')
    peername = process.get_extra_info('remote_peername')

    logger.warning('[%s/%s] NewConn: command=[%s]', username, peername, command)

    if not command:
        process.exit(1)

    args = process.command.split()
    role = args[0]
    try:
        cfg = config['roles'][role]
    except KeyError:
        stderr.write('Invalid command\n')
        process.exit(2)

    hostname = None
    if cfg.get('require_host', True):
        if len(args) == 1:
            stderr.write('Usage: deplot|dev hostname\n')
            process.exit(3)
        else:
            hostname = args[1]

    if username not in cfg['users']:
        stderr.write('permission denied\n')
        process.exit(4)

    try:
        cert = generate_user_cert(role, hostname, username, cfg)
        stdout.write(cert.export_certificate().decode('utf-8'))
        logger.warning('[%s/%s] NewCert: serial=%u, comment=%s', username, peername, cert._serial, cert.get_comment())
    except Exception as e:
        stderr.write(str(e))

    process.exit(0)


class MySSHServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        self._conn = conn

    def begin_auth(self, username):
        try:
            self._conn.set_authorized_keys(get_user_pubkey(username))
        except IOError:
            pass

        return True


async def start_server():
    await asyncssh.create_server(MySSHServer, '', 65022, server_host_keys=[config['ssh_host_key']], process_factory=handle_client)


def main(args):
    """ Entry Point """
    global ca, config

    logging.basicConfig()
    config = json.load(open(args.config, 'r'))
    asyncssh.set_log_level(config.get('loglevel', 10))

    ca = load_ca(config['ca'])

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(start_server())
    except (OSError, asyncssh.Error) as exc:
        sys.exit('Error starting server: ' + str(exc))

    loop.run_forever()


if __name__ == '__main__':
    def parse_cmdline():
        """ cmd parse """
        import argparse

        parser = argparse.ArgumentParser(description="SSH CA Service")
        parser.add_argument('-c', '--config', default='/etc/sshca/config.json', help='Config file')
        parser.add_argument('--debug', action='store_true', help='Run in debug mode')
        args = parser.parse_args()

        return args

    main(parse_cmdline())
