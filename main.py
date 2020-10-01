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


class CertError(Exception):
    """Error types"""
    def __init__(self, errno, msg):
        """Init"""
        self.errno = errno
        self.msg = msg


def get_user_pubkey(username):
    """username -> public key path"""
    return os.path.join(config['user_key_path'], '%s.pub' % username)


def load_ca(path):
    """Load CA private key"""
    password = getpass.getpass(prompt='Input the CA password: ')
    cert = asyncssh.read_private_key(path, passphrase=password)
    return cert


def generate_user_cert(role, hostname, username):
    """Generate a Signed user cert
    KeyID: username
    Serial: Current Unix Time
    Principals: role@hostname or role
    """
    try:
        cfg = config['roles'][role]
    except KeyError:
        raise CertError(101, "Invalid role")

    if cfg.get('require_host', True) and not hostname:
        raise CertError(102, "Require hostname")

    if username not in cfg['users']:
        raise CertError(103, "Permission denied")

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


class MySFTPServer(asyncssh.SFTPServer):
    NO_SUCH_FILE = b'/N0-SuCh-Fi1e'

    def __init__(self, chan):
        root = os.path.join(config['user_cert_path'], chan.get_extra_info('username'))
        os.makedirs(root, exist_ok=True)
        super().__init__(chan, chroot=root)
        self.root = root


    def map_path(self, path):
        """Generate user requested cert file"""
        chan = self.channel
        try:
            spath = path.decode('utf-8')
        except:
            return self.NO_SUCH_FILE

        username = chan.get_extra_info('username')
        peername = chan.get_extra_info('remote_peername')
        self.logger.warning('[%s/%s] NewSftp: path=[%s]', username, peername, spath)

        if not spath.endswith('.pub'):
            return self.NO_SUCH_FILE

        #Path is: role-hostname.pub or role.pub
        items = spath[:-4].split('-')
        role = items[0]
        hostname = items[1] if len(items) > 1 else None

        try:
            cert = generate_user_cert(role, hostname, username)
            self.logger.warning('[%s/%s] NewCert: serial=%u, comment=%s', username, peername, cert._serial, cert.get_comment())
        except CertError as err:
            self.logger.error(err.msg)
            chan.write_stderr(err.msg)
            chan.exit(err.errno)
    
        opath = os.path.join(self.root, spath)
        cert.write_certificate(opath)
        return asyncssh.SFTPServer.map_path(self, path)


def handle_client(process):
    """Handle a SSH connect"""
    stdout, stderr, logger, command = process.stdout, process.stderr, process.logger, process.command
    username = process.get_extra_info('username')
    peername = process.get_extra_info('remote_peername')

    logger.warning('[%s/%s] NewConn: command=[%s]', username, peername, command)

    if not command:
        process.exit(1)

    #command is: role [hostname]
    args = process.command.split()
    role = args[0]
    hostname = args[1] if len(args) > 1 else None

    try:
        cert = generate_user_cert(role, hostname, username)
    except CertError as err:
        stderr.write('Err: %s\n' % err.msg)
        process.exit(err.errno)

    stdout.write(cert.export_certificate().decode('utf-8'))
    logger.warning('[%s/%s] NewCert: serial=%u, comment=%s', username, peername, cert._serial, cert.get_comment())
    process.exit(0)


class MySSHServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        self._conn = conn

    def begin_auth(self, username):
        """Auth user by public key"""
        try:
            self._conn.set_authorized_keys(get_user_pubkey(username))
        except IOError:
            pass

        return True


async def start_server():
    if config.get('enable_scp', False):
        scp_options = {'sftp_factory': MySFTPServer, 'allow_scp': True}
    else:
        scp_options = {}

    await asyncssh.create_server(MySSHServer, '', config.get('port', 65022), server_host_keys=[config['ssh_host_key']], process_factory=handle_client, **scp_options)


def main(args):
    """ Entry Point """
    global ca, config

    logging.basicConfig()
    config = json.load(open(args.config, 'r'))
    if args.debug:
        asyncssh.set_debug_level(2)
        asyncssh.set_log_level(0)
    else:
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
