from slips_files.common.imports import *
import platform
import sys
import os
import shutil
import json
import subprocess
import time

class Blocking(Module, multiprocessing.Process):
    """Data should be passed to this module as a json encoded python dict,
    by default this module flushes all slipsBlocking chains before it starts"""
    name = 'Blocking'
    description = 'Block malicious IPs connecting to this device'
    authors = ['Sebastian Garcia, Alya Gomaa']
    def init(self):
        self.c1 = self.db.subscribe('new_blocking')
        self.channels = {
            'new_blocking': self.c1,
        }
        self.os = platform.system()
        if self.os == 'Darwin':
            self.print('Mac OS blocking is not supported yet.')
            sys.exit()
        self.firewall = self.determine_linux_firewall()
        self.set_sudo_according_to_env()
        self.initialize_chains_in_firewall()
        self.unblock_ips = {}


    def test(self):
        """For debugging purposes, once we're done with the module we'll delete it"""

        if not self.is_ip_blocked('2.2.0.0'):
            blocking_data = {
                'ip': '2.2.0.0',
                'block': True,
                'from': True,
                'to': True,
                'block_for': 5
            }
            blocking_data = json.dumps(blocking_data)
            self.db.publish('new_blocking', blocking_data)
            self.print('[test] Blocked ip.')
        else:
            self.print('[test] IP is already blocked')

    def set_sudo_according_to_env(self):
        """Check if running in host or in docker and sets sudo string accordingly.
        There's no sudo in docker so we need to execute all commands without it
        """
        self.running_in_docker = os.environ.get(
            'IS_IN_A_DOCKER_CONTAINER', False
        )
        self.sudo = '' if self.running_in_docker else 'sudo '


    def determine_linux_firewall(self):
        """Returns the currently installed firewall and installs iptables if none was found"""

        if shutil.which('iptables'):
            return 'iptables'
        elif shutil.which('nftables'):
            return 'nftables'
        else:
            self.print(
                'iptables is not installed. Blocking module is quitting.'
            )
            sys.exit()

    def delete_slipsBlocking_chain(self):
        """Flushes and deletes everything in slipsBlocking chain"""
        chain_exists = (
            os.system(f'{self.sudo}iptables -nvL slipsBlocking >/dev/null 2>&1')
            == 0
        )
        if self.firewall == 'iptables' and chain_exists:
            cmd = f'{self.sudo}iptables -D INPUT -j slipsBlocking >/dev/null 2>&1 ; {self.sudo}iptables -D OUTPUT -j slipsBlocking >/dev/null 2>&1 ; {self.sudo}iptables -D FORWARD -j slipsBlocking >/dev/null 2>&1'
            os.system(cmd)
            cmd = f'{self.sudo}iptables -F slipsBlocking >/dev/null 2>&1 ; {self.sudo} iptables -X slipsBlocking >/dev/null 2>&1'
            os.system(cmd)
            print('Successfully deleted slipsBlocking chain.')
            return True
        elif self.firewall == 'nftables':
            os.system(f'{self.sudo}nft flush chain inet slipsBlocking')
            os.system(f'{self.sudo}nft delete chain inet slipsBlocking')
            return True
        return False

    def get_cmd_output(self, command):
        """Executes a command and returns the output"""

        result = subprocess.run(command.split(), stdout=subprocess.PIPE)
        return result.stdout.decode('utf-8')

    def initialize_chains_in_firewall(self):
        """For linux: Adds a chain to iptables or a table to nftables called
        slipsBlocking where all the rules will reside"""

        if self.firewall == 'iptables':
            self.print('Executing "sudo iptables -N slipsBlocking"', 6, 0)
            os.system(f'{self.sudo}iptables -N slipsBlocking >/dev/null 2>&1')

            INPUT_chain_rules = self.get_cmd_output(f'{self.sudo} iptables -nvL INPUT')
            OUTPUT_chain_rules = self.get_cmd_output(f'{self.sudo} iptables -nvL OUTPUT')
            FORWARD_chain_rules = self.get_cmd_output(f'{self.sudo} iptables -nvL FORWARD')
            if 'slipsBlocking' not in INPUT_chain_rules:
                os.system(
                    self.sudo
                    + 'iptables -I INPUT -j slipsBlocking >/dev/null 2>&1'
                )
            if 'slipsBlocking' not in OUTPUT_chain_rules:
                os.system(
                    self.sudo
                    + 'iptables -I OUTPUT -j slipsBlocking >/dev/null 2>&1'
                )
            if 'slipsBlocking' not in FORWARD_chain_rules:
                os.system(
                    self.sudo
                    + 'iptables -I FORWARD -j slipsBlocking >/dev/null 2>&1'
                )

        elif self.firewall == 'nftables':
            self.print(
                'Executing "sudo nft add table inet slipsBlocking"', 6, 0
            )
            os.system(f'{self.sudo}nft add table inet slipsBlocking')

    def exec_iptables_command(self, action, ip_to_block, flag, options):
        """
        Constructs the iptables rule/command based on the options sent in the message
        flag options:
          -s : to block traffic from source ip
          -d : to block to destination ip
        action options:
          insert : to insert a new rule at the top of slipsBlocking list
          delete : to delete an existing rule
        """

        command = f'{self.sudo}iptables --{action} slipsBlocking {flag} {ip_to_block} ' \
                  f'-m comment --comment "Slips rule" >/dev/null 2>&1'
        for key in options.keys():
            command += options[key]
        command += ' -j DROP'
        exit_status = os.system(command)

        return exit_status == 0

    def is_ip_blocked(self, ip) -> bool:
        """Checks if ip is already blocked or not"""

        command = f'{self.sudo}iptables -L slipsBlocking -v -n'
        # Execute command
        result = subprocess.run(command.split(), stdout=subprocess.PIPE)
        result = result.stdout.decode('utf-8')
        return ip in result

    def block_ip(
        self,
        ip_to_block=None,
        from_=True,
        to=True,
        dport=None,
        sport=None,
        protocol=None,
        block_for=False,
    ):
        """
        This function determines the user's platform and firewall and calls
        the appropriate function to add the rules to the used firewall.
        By default this function blocks all traffic from and to the given ip.
        """

        if type(ip_to_block) != str:
            return False

        if self.is_ip_blocked(ip_to_block):
            return False

        if (
            self.firewall == 'iptables'
        ):
            if from_ is None and to is None:
                from_, to = True, True
            options = {
                'protocol': f' -p {protocol}' if protocol is not None else '',
                'dport': f' --dport {str(dport)}' if dport is not None else '',
                'sport': f' --sport {str(sport)}' if sport is not None else '',
            }

            if from_:
                blocked = self.exec_iptables_command(
                    action='insert',
                    ip_to_block=ip_to_block,
                    flag='-s',
                    options=options,
                )
                if blocked:
                    self.print(f'Blocked all traffic from: {ip_to_block}')

            if to:
                blocked = self.exec_iptables_command(
                    action='insert',
                    ip_to_block=ip_to_block,
                    flag='-d',
                    options=options,
                )
                if blocked:
                    self.print(f'Blocked all traffic to: {ip_to_block}')

            if block_for:
                time_of_blocking = time.time()
                self.unblock_ips.update(
                    {
                        ip_to_block: {
                            'block_for': block_for,
                            'time_of_blocking': time_of_blocking,
                            'blocking_details': {
                                'from': from_,
                                'to': to,
                                'dport': dport,
                                'sport': sport,
                                'protocol': protocol,
                            },
                        }
                    }
                )

            if blocked:
                return True

        return False

    def unblock_ip(
        self,
        ip_to_unblock,
        from_=None,
        to=None,
        dport=None,
        sport=None,
        protocol=None,
    ):
        """Unblocks an ip based on the flags passed in the message"""
        options = {
            'protocol': f' -p {protocol}' if protocol else '',
            'dport': f' --dport {dport}' if dport else '',
            'sport': f' --sport {sport}' if sport else '',
        }
        if from_ is None and to is None:
            from_, to = True, True
        if from_:
            unblocked = self.exec_iptables_command(
                action='delete',
                ip_to_block=ip_to_unblock,
                flag='-s',
                options=options,
            )
        if to:
            unblocked = self.exec_iptables_command(
                action='delete',
                ip_to_block=ip_to_unblock,
                flag='-d',
                options=options,
            )

        if unblocked:
            self.print(f'Unblocked: {ip_to_unblock}')
            return True
        return False

    def check_for_ips_to_unblock(self):
            unblocked_ips = set()
            # check if any ip needs to be unblocked
            for ip, info in self.unblock_ips.items():
                if (
                    time.time()
                    >= info['time_of_blocking'] + info['block_for']
                ):
                    blocking_details = info['blocking_details']
                    self.unblock_ip(
                        ip,
                        blocking_details['from'],
                        blocking_details['to'],
                        blocking_details['dport'],
                        blocking_details['sport'],
                        blocking_details['protocol'],
                    )
                    # make a list of unblocked IPs to remove from dict
                    unblocked_ips.add(ip)

            for ip in unblocked_ips:
                self.unblock_ips.pop(ip)

    def main(self):
        if msg := self.get_msg('new_blocking'):
            data = json.loads(msg['data'])
            ip = data.get('ip')
            block = data.get('block')
            from_ = data.get('from')
            to = data.get('to')
            dport = data.get('dport')
            sport = data.get('sport')
            protocol = data.get('protocol')
            block_for = data.get('block_for')
            if block:
                self.block_ip(
                    ip, from_, to, dport, sport, protocol, block_for
                )
            else:
                self.unblock_ip(ip, from_, to, dport, sport, protocol)
        self.check_for_ips_to_unblock()

