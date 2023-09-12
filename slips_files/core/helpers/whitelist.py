import json
import ipaddress
import validators
from slips_files.common.imports import *
import tld
import os


class Whitelist:
    def __init__(self, output_queue, db):
        self.name = 'whitelist'
        self.output_queue = output_queue
        self.read_configuration()
        self.org_info_path = 'slips_files/organizations_info/'
        self.ignored_flow_types = ('arp')
        self.db = db

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.output_queue.put(f'{levels}|{self.name}|{text}')

    def read_configuration(self):
        conf = ConfigParser()
        self.whitelist_path = conf.whitelist_path()

    def is_whitelisted_asn(self, ip, org):
        ip_data = self.db.getIPData(ip)
        try:
            ip_asn = ip_data['asn']['asnorg']
            org_asn = json.loads(self.db.get_org_info(org, 'asn'))
            if (
                ip_asn
                and ip_asn != 'Unknown'
                and (org.lower() in ip_asn.lower() or ip_asn in org_asn)
            ):



                return True
        except (KeyError, TypeError):

            pass

    def is_ignored_flow_type(self, flow_type) -> bool:
        """
        Function reduce the number of checks we make if we don't need to check this type of flow
        """
        if flow_type in self.ignored_flow_types:
            return True


    def is_whitelisted_domain_in_flow(
            self, whitelisted_domain, direction, domains_of_flow, ignore_type
    ):
        """
        Given the domain of a flow, and a whitelisted domain,
        this function checks any of the flow domains
        is a subdomain or the same domain as the whitelisted domain

        :param whitelisted_domain: the domain we want to check if it exists in the domains_of_flow
        :param ignore_type: alerts or flows or both
        :param direction: src or dst or both
        :param domains_of_flow: src domains of the src IP of the flow,
                                or dst domains of the dst IP of the flow
        """
        whitelisted_domains = self.db.get_whitelist('domains')
        if not whitelisted_domains:
            return False


        from_ = whitelisted_domains[whitelisted_domain]['from']

        if direction in from_ or 'both' in from_:
            what_to_ignore = whitelisted_domains[whitelisted_domain]['what_to_ignore']

            for domain_to_check in domains_of_flow:
                main_domain = domain_to_check[-len(whitelisted_domain) :]
                if whitelisted_domain in main_domain:

                    if (
                        ignore_type in what_to_ignore
                        or 'both' in what_to_ignore
                    ):
                        return True
        return False

    def is_whitelisted_domain(self, domain_to_check, saddr, daddr, ignore_type):
        """
        Used only when checking whitelisted flows
        (aka domains associated with the src or dstip of a flow)
        :param domain_to_check: the domain we want to know if whitelisted or not
        :param saddr: saddr of the flow we're checking
        :param daddr: daddr of the flow we're checking
        :param ignore_type: what did the user whitelist? alerts or flows or both
        """

        whitelisted_domains = self.db.get_whitelist('domains')
        if not whitelisted_domains:
            return False


        (
            dst_domains_of_flow,
            src_domains_of_flow,
        ) = self.get_domains_of_flow(saddr, daddr)



        for whitelisted_domain in list(whitelisted_domains.keys()):
            what_to_ignore = whitelisted_domains[whitelisted_domain]['what_to_ignore']



            main_domain = domain_to_check[-len(whitelisted_domain) :]
            if whitelisted_domain in main_domain:

                if (
                    ignore_type in what_to_ignore
                    or 'both' in what_to_ignore
                ):

                    return True


            if self.is_whitelisted_domain_in_flow(whitelisted_domain, 'src', src_domains_of_flow, ignore_type):


                return True

            if self.is_whitelisted_domain_in_flow(whitelisted_domain, 'dst', dst_domains_of_flow, ignore_type):


                return True
        return False


    def is_whitelisted_flow(self, flow) -> bool:
        """
        Checks if the src IP or dst IP or domain or organization of this flow is whitelisted.
        """
        saddr = flow.saddr
        daddr = flow.daddr
        flow_type = flow.type_

        (
            domains_to_check_dst,
            domains_to_check_src,
        ) = self.get_domains_of_flow(saddr, daddr)





        domains_to_check = []
        if flow_type == 'ssl':
            domains_to_check.append(flow.server_name)
        elif flow_type == 'http':
            domains_to_check.append(flow.host)
        elif flow_type == 'ssl':
            domains_to_check.append(flow.subject.replace(
                'CN=', ''
            ))

        for domain in domains_to_check:
            if self.is_whitelisted_domain(domain, saddr, daddr, 'flows'):
                return True


        if whitelisted_IPs := self.db.get_whitelist('IPs'):


            ips_to_whitelist = list(whitelisted_IPs.keys())

            if saddr in ips_to_whitelist:

                from_ = whitelisted_IPs[saddr]['from']
                what_to_ignore = whitelisted_IPs[saddr]['what_to_ignore']
                if ('src' in from_ or 'both' in from_) and (
                        self.should_ignore_flows(what_to_ignore)
                ):

                    return True

            if daddr in ips_to_whitelist:

                from_ = whitelisted_IPs[daddr]['from']
                what_to_ignore = whitelisted_IPs[daddr]['what_to_ignore']
                if ('dst' in from_ or 'both' in from_) and (
                    self.should_ignore_flows(what_to_ignore)
                ):

                    return True

        if whitelisted_macs := self.db.get_whitelist('mac'):

            src_mac = flow.smac if hasattr(flow, 'smac') else False

            if not src_mac:
                if src_mac := self.db.get_mac_addr_from_profile(
                    f'profile_{saddr}'
                ):
                    src_mac = src_mac[0]

            if src_mac and src_mac in list(whitelisted_macs.keys()):

                from_ = whitelisted_macs[src_mac]['from']
                what_to_ignore = whitelisted_macs[src_mac]['what_to_ignore']

                if (
                    ('src' in from_ or 'both' in from_)
                    and
                    self.should_ignore_flows(what_to_ignore)
                ):

                    return True

            dst_mac = flow.dmac if hasattr(flow, 'smac') else False
            if dst_mac and dst_mac in list(whitelisted_macs.keys()):

                from_ = whitelisted_macs[dst_mac]['from']
                what_to_ignore = whitelisted_macs[dst_mac]['what_to_ignore']

                if (
                    ('dst' in from_ or 'both' in from_)
                    and
                    self.should_ignore_flows(what_to_ignore)
                ):

                    return True

        if self.is_ignored_flow_type(flow_type):
            return False

        if whitelisted_orgs := self.db.get_whitelist('organizations'):




            for org in whitelisted_orgs:
                from_ = whitelisted_orgs[org]['from']
                what_to_ignore = whitelisted_orgs[org][
                    'what_to_ignore'
                ]


                if self.should_ignore_flows(what_to_ignore):

                    if 'both' in from_:
                        domains_to_check = (
                            domains_to_check_src + domains_to_check_dst
                        )
                    elif 'src' in from_:
                        domains_to_check = domains_to_check_src
                    elif 'dst' in from_:
                        domains_to_check = domains_to_check_dst

                    if 'src' in from_ or 'both' in from_:

                        try:
                            if self.is_ip_in_org(saddr, org):

                                return True
                        except ValueError:

                            return False


                        if self.is_whitelisted_asn(saddr, org):


                            return True

                    if 'dst' in from_ or 'both' in from_:

                        try:
                            if self.is_ip_in_org(flow.daddr, org):


                                return True
                        except ValueError:

                            return False


                        if self.is_whitelisted_asn(daddr, org):

                            return True




                    for flow_domain in domains_to_check:
                        if self.is_domain_in_org(flow_domain, org):
                            return True

        return False

    def is_domain_in_org(self, domain, org):
        """
        Checks if the given domains belongs to the given org
        """
        try:
            org_domains = json.loads(
                self.db.get_org_info(org, 'domains')
            )
            if org in domain:

                return True

            try:
                flow_TLD = tld.get_tld(domain, as_object=True)
            except tld.exceptions.TldBadUrl:
                flow_TLD = domain.split('.')[-1]

            for org_domain in org_domains:
                try:
                    org_domain_TLD = tld.get_tld(org_domain, as_object=True)
                except tld.exceptions.TldBadUrl:
                    org_domain_TLD = org_domain.split('.')[-1]


                if flow_TLD != org_domain_TLD:
                    continue



                if org_domain in domain:


                    return True

                if domain in org_domain:


                    return True
        except (KeyError, TypeError):



            pass

    def read_whitelist(self):
        """Reads the content of whitelist.conf and stores information about each ip/org/domain in the database"""



        whitelisted_IPs = self.db.get_whitelist('IPs')
        whitelisted_domains = self.db.get_whitelist('domains')
        whitelisted_orgs = self.db.get_whitelist('organizations')
        whitelisted_mac = self.db.get_whitelist('mac')

        line_number = 0
        try:
            with open(self.whitelist_path) as whitelist:

                while line := whitelist.readline():
                    line_number += 1
                    if line.startswith('"IoCType"'):
                        continue


                    if line.startswith('#'):
                        if whitelisted_IPs:
                            for ip in list(whitelisted_IPs):

                                if (
                                    ip in line
                                    and whitelisted_IPs[ip]['from'] in line
                                    and whitelisted_IPs[ip]['what_to_ignore']
                                    in line
                                ):

                                    whitelisted_IPs.pop(ip)
                                    break

                        if whitelisted_domains:
                            for domain in list(whitelisted_domains):
                                if (
                                    domain in line
                                    and whitelisted_domains[domain]['from']
                                    in line
                                    and whitelisted_domains[domain][
                                        'what_to_ignore'
                                    ]
                                    in line
                                ):

                                    whitelisted_domains.pop(domain)
                                    break

                        if whitelisted_orgs:
                            for org in list(whitelisted_orgs):
                                if (
                                    org in line
                                    and whitelisted_orgs[org]['from'] in line
                                    and whitelisted_orgs[org]['what_to_ignore']
                                    in line
                                ):

                                    whitelisted_orgs.pop(org)
                                    break



                        continue

                    line = line.replace('\n', '').replace(' ', '').split(',')
                    try:
                        type_, data, from_, what_to_ignore = (
                            (line[0]).lower(),
                            line[1],
                            line[2],
                            line[3],
                        )
                    except IndexError:

                        self.print(
                            f'Line {line_number} in whitelist.conf is missing a column. Skipping.'
                        )
                        continue


                    try:
                        if 'ip' in type_ and (
                            validators.ip_address.ipv6(data)
                            or validators.ip_address.ipv4(data)
                        ):
                            whitelisted_IPs[data] = {
                                'from': from_,
                                'what_to_ignore': what_to_ignore,
                            }
                        elif 'domain' in type_ and validators.domain(data):
                            whitelisted_domains[data] = {
                                'from': from_,
                                'what_to_ignore': what_to_ignore,
                            }
                        elif 'mac' in type_ and validators.mac_address(data):
                            whitelisted_mac[data] = {
                                'from': from_,
                                'what_to_ignore': what_to_ignore,
                            }
                        elif 'org' in type_:
                            if data not in utils.supported_orgs:
                                self.print(f"Whitelisted org {data} is not supported in slips")
                                continue




                            try:

                                whitelisted_orgs[data]['from'] = from_
                                whitelisted_orgs[data][
                                    'what_to_ignore'
                                ] = what_to_ignore
                            except KeyError:

                                whitelisted_orgs[data] = {
                                    'from': from_,
                                    'what_to_ignore': what_to_ignore,
                                }

                        else:
                            self.print(f'{data} is not a valid {type_}.', 1, 0)
                    except Exception:
                        self.print(
                            f'Line {line_number} in whitelist.conf is invalid. Skipping. '
                        )
        except FileNotFoundError:
            self.print(
                f"Can't find {self.whitelist_path}, using slips default whitelist.conf instead"
            )
            if self.whitelist_path != 'config/whitelist.conf':
                self.whitelist_path = 'config/whitelist.conf'
                self.read_whitelist()


        self.db.set_whitelist('IPs', whitelisted_IPs)
        self.db.set_whitelist('domains', whitelisted_domains)
        self.db.set_whitelist('organizations', whitelisted_orgs)
        self.db.set_whitelist('mac', whitelisted_mac)

        return whitelisted_IPs, whitelisted_domains, whitelisted_orgs, whitelisted_mac

    def get_domains_of_flow(self, saddr, daddr):
        """
        Returns the domains of each ip (src and dst) that appeard in this flow
        """


        domains_to_check_src = []
        domains_to_check_dst = []
        try:
            if ip_data := self.db.getIPData(saddr):
                if sni_info := ip_data.get('SNI', [{}])[0]:
                    domains_to_check_src.append(sni_info.get('server_name', ''))
        except (KeyError, TypeError):
            pass
        try:

            src_dns_domains = self.db.get_dns_resolution(saddr)
            src_dns_domains = src_dns_domains.get('domains', [])
            domains_to_check_src.extend(iter(src_dns_domains))
        except (KeyError, TypeError):
            pass
        try:
            if ip_data := self.db.getIPData(daddr):
                if sni_info := ip_data.get('SNI', [{}])[0]:
                    domains_to_check_dst.append(sni_info.get('server_name'))
        except (KeyError, TypeError):
            pass

        try:

            dst_dns_domains = self.db.get_dns_resolution(daddr)
            dst_dns_domains = dst_dns_domains.get('domains', [])
            domains_to_check_dst.extend(iter(dst_dns_domains))
        except (KeyError, TypeError):
            pass

        return domains_to_check_dst, domains_to_check_src

    def is_ip_in_org(self, ip:str, org):
        """
        Check if the given ip belongs to the given org
        """
        try:
            org_subnets: dict = self.db.get_org_IPs(org)

            first_octet:str = utils.get_first_octet(ip)
            if not first_octet:
                return
            ip_obj = ipaddress.ip_address(ip)

            for range in org_subnets.get(first_octet, []):
                if ip_obj in ipaddress.ip_network(range):
                    return True
        except (KeyError, TypeError):



            pass
        return False

    def profile_has_whitelisted_mac(
            self, profile_ip, whitelisted_macs, is_srcip, is_dstip
    ) -> bool:
        """
        Checks for alerts whitelist
        """
        mac = self.db.get_mac_addr_from_profile(
            f'profile_{profile_ip}'
        )

        if not mac:

            return False

        mac = mac[0]
        if mac in list(whitelisted_macs.keys()):

            from_ = whitelisted_macs[mac]['from']
            what_to_ignore = whitelisted_macs[mac]['what_to_ignore']

            if (
                'alerts' in what_to_ignore
                or 'both' in what_to_ignore
            ):
                if is_srcip and (
                    'src' in from_ or 'both' in from_
                ):
                    return True
                if is_dstip and (
                    'dst' in from_ or 'both' in from_
                ):
                    return True

    def is_ip_asn_in_org_asn(self, ip, org):
        """
        returns true if the ASN of the given IP is listed in the ASNs of the given org ASNs
        """

        ip_data = self.db.getIPData(ip)
        if not ip_data:
            return
        try:
            ip_asn = ip_data['asn']['number']
        except KeyError:
            return

        org_asn: list = json.loads(self.db.get_org_info(org, 'asn'))


        if (
            org.lower() in ip_asn.lower()
            or ip_asn in org_asn
        ):



            return True

    def is_srcip(self, attacker_direction):
        return attacker_direction in ('sip', 'srcip', 'sport', 'inTuple')

    def is_dstip(self, attacker_direction):
        return attacker_direction in ('dip', 'dstip', 'dport', 'outTuple')

    def should_ignore_from(self, direction) -> bool:
        """
        Returns true if the user wants to whitelist alerts/flows from this source(ip, org, mac, etc)
        """
        return ('src' in direction or 'both' in direction)

    def should_ignore_to(self, direction) -> bool:
        """
        Returns true if the user wants to whitelist alerts/flows to this source(ip, org, mac, etc)
        """
        return ('dst' in direction or 'both' in direction)

    def should_ignore_alerts(self, what_to_ignore)-> bool:
        """
        returns true we if the user wants to ignore alerts
        """
        return 'alerts' in what_to_ignore or 'both' in what_to_ignore

    def should_ignore_flows(self, what_to_ignore)-> bool:
        """
        returns true we if the user wants to ignore alerts
        """
        return 'flows' in what_to_ignore or 'both' in what_to_ignore

    def parse_whitelist(self, whitelist):
        """
        returns a tuple with whitelisted IPs, domains, orgs and MACs
        """
        try:

            whitelisted_IPs = json.loads(whitelist['IPs'])
        except (IndexError, KeyError):
            whitelisted_IPs = {}
        try:
            whitelisted_domains = json.loads(whitelist['domains'])
        except (IndexError, KeyError):
            whitelisted_domains = {}
        try:
            whitelisted_orgs = json.loads(whitelist['organizations'])
        except (IndexError, KeyError):
            whitelisted_orgs = {}
        try:
            whitelisted_macs = json.loads(whitelist['mac'])
        except (IndexError, KeyError):
            whitelisted_macs = {}
        return whitelisted_IPs, whitelisted_domains, whitelisted_orgs, whitelisted_macs


    def is_whitelisted_evidence(
            self, srcip, attacker, attacker_direction, description, victim
        ) -> bool:
        """
        Checks if IP is whitelisted
        :param srcip: Src IP that generated the evidence
        :param attacker: This is what was detected in the evidence. (attacker) can be ip, domain, tuple(ip:port:proto).
        :param attacker_direction: this is the type of the attacker param. 'sip', 'dip', 'sport', 'dport', 'inTuple',
        'outTuple', 'dstdomain'
        :param description: may contain IPs if the evidence is coming from portscan module
        :param victim: ip of the victim (will either be the saddr, the daddr, or '' in case of scans)
        """



        whitelist = self.db.get_all_whitelist()
        max_tries = 10




        while not bool(whitelist) and max_tries != 0:

            max_tries -= 1
            whitelist = self.db.get_all_whitelist()
        if max_tries == 0:

            return False

        if self.check_whitelisted_attacker(attacker, attacker_direction):
            return True

        if self.check_whitelisted_victim(victim, srcip):
            return True

    def check_whitelisted_victim(self, victim, srcip):
        if not victim:
            return False

        whitelist = self.db.get_all_whitelist()
        whitelisted_IPs, whitelisted_domains, whitelisted_orgs, whitelisted_macs = self.parse_whitelist(whitelist)

        victim = victim.strip()
        victim_type = utils.detect_data_type(victim)

        if victim_type == 'ip':
            ip = victim
            is_srcip = True if srcip in victim else False
            if self.is_ip_whitelisted(ip, is_srcip):
                return True

        elif victim_type == 'domain':

            if self.is_domain_whitelisted(victim, 'dstdomain'):
                return True

        direction = 'src' if srcip in victim else 'dst'
        if (
                whitelisted_orgs
                and self.is_part_of_a_whitelisted_org(victim, victim_type, direction)
        ):
            return True


    def check_whitelisted_attacker(self, attacker, attacker_direction):

        whitelist = self.db.get_all_whitelist()
        whitelisted_IPs, whitelisted_domains, whitelisted_orgs, whitelisted_macs = self.parse_whitelist(whitelist)


        if 'domain' in attacker_direction:
            attacker_type = 'domain'
        elif 'outTuple' in attacker_direction:

            attacker = attacker.split('-')[0]
            attacker_type = 'ip'
        else:

            attacker_type = 'ip'


        if attacker_type == 'domain':
            if self.is_domain_whitelisted(attacker, attacker_direction):
                return True

        elif attacker_type == 'ip':


            ip = attacker
            is_srcip = self.is_srcip(attacker_direction)

            if self.is_ip_whitelisted(ip, is_srcip):
                return True


        if (
                whitelisted_orgs
                and self.is_part_of_a_whitelisted_org(attacker, attacker_type, attacker_direction)
        ):
               return True

        return False

    def load_org_asn(self, org) -> list:
        """
        Reads the specified org's asn from slips_files/organizations_info and stores the info in the database
        org: 'google', 'facebook', 'twitter', etc...
        returns a list containing the org's asn
        """
        try:

            org_asn = []
            asn_info_file = os.path.join(self.org_info_path, f'{org}_asn')
            with open(asn_info_file, 'r') as f:
                while line := f.readline():

                    line = line.replace('\n', '').strip()

                    org_asn.append(line.upper())

        except (FileNotFoundError, IOError):


            asn_cache: dict = self.db.get_asn_cache()
            org_asn = []

            for octet, range_info in asn_cache.items:

                range_info = json.loads(range_info)
                for range, asn_info in range_info.items():

                    if org in asn_info['org'].lower():
                        org_asn.append(org)

        self.db.set_org_info(org, json.dumps(org_asn), 'asn')
        return org_asn

    def load_org_domains(self, org):
        """
        Reads the specified org's domains from slips_files/organizations_info and stores the info in the database
        org: 'google', 'facebook', 'twitter', etc...
        returns a list containing the org's domains
        """
        try:
            domains = []

            domain_info_file = os.path.join(self.org_info_path, f'{org}_domains')
            with open(domain_info_file, 'r') as f:
                while line := f.readline():

                    line = line.replace('\n', '').strip()
                    domains.append(line.lower())

        except (FileNotFoundError, IOError):
            return False

        self.db.set_org_info(org, json.dumps(domains), 'domains')
        return domains

    def load_org_IPs(self, org):
        """
        Reads the specified org's info from slips_files/organizations_info and stores the info in the database
        if there's no file for this org, it get the IP ranges from asnlookup.com
        org: 'google', 'facebook', 'twitter', etc...
        returns a list of this organization's subnets
        """
        if org not in utils.supported_orgs:
            return

        org_info_file = os.path.join(self.org_info_path, org)
        try:


            org_subnets = {}
            with open(org_info_file, 'r') as f:
                while line := f.readline():

                    line = line.replace('\n', '').strip()
                    try:

                        ipaddress.ip_network(line)
                    except ValueError:

                        continue

                    first_octet = utils.get_first_octet(line)
                    if not first_octet:
                        line = f.readline()
                        continue

                    try:
                        org_subnets[first_octet].append(line)
                    except KeyError:
                        org_subnets[first_octet] = [line]

        except (FileNotFoundError, IOError):

            return


        self.db.set_org_info(org, json.dumps(org_subnets), 'IPs')
        return org_subnets

    def is_ip_whitelisted(self, ip: str, is_srcip: bool):
        """
        checks the given IP in the whitelisted IPs read from whitelist.conf
        """
        whitelist = self.db.get_all_whitelist()
        whitelisted_IPs, whitelisted_domains, whitelisted_orgs, whitelisted_macs = self.parse_whitelist(whitelist)

        is_dstip = not is_srcip
        if ip in whitelisted_IPs:



            direction = whitelisted_IPs[ip]['from']
            what_to_ignore = whitelisted_IPs[ip]['what_to_ignore']
            ignore_alerts = self.should_ignore_alerts(what_to_ignore)

            ignore_alerts_from_ip = (
                ignore_alerts
                and is_srcip
                and self.should_ignore_from(direction)
            )
            ignore_alerts_to_ip = (
                ignore_alerts
                and is_dstip
                and self.should_ignore_to(direction)
            )
            if ignore_alerts_from_ip or ignore_alerts_to_ip:



                return True



            if whitelisted_macs and self.profile_has_whitelisted_mac(
                ip, whitelisted_macs, is_srcip, is_dstip
            ):
                return True

    def is_domain_whitelisted(self, domain: str, direction: str):
        """
        :param direction: can be either srcdomain or dstdomain
        """

        is_srcdomain = direction in ('srcdomain')
        is_dstdomain = direction in ('dstdomain')


        try:
            domain = tld.get_fld(domain, fix_protocol=True)
        except (tld.exceptions.TldBadUrl, tld.exceptions.TldDomainNotFound):
            for str_ in ('http://', 'https://','www'):
                domain = domain.replace(str_, "")

        whitelist = self.db.get_all_whitelist()
        whitelisted_domains = self.parse_whitelist(whitelist)[1]


        for domain_in_whitelist in whitelisted_domains:

            sub_domain = domain[-len(domain_in_whitelist) :]
            if domain_in_whitelist in sub_domain:

                direction = whitelisted_domains[sub_domain]['from']

                what_to_ignore = whitelisted_domains[sub_domain][
                    'what_to_ignore'
                ]
                ignore_alerts = self.should_ignore_alerts(what_to_ignore)
                ignore_alerts_from_domain = (
                    ignore_alerts
                    and is_srcdomain
                    and self.should_ignore_from(direction)
                )
                ignore_alerts_to_domain = (
                    ignore_alerts
                    and is_dstdomain
                    and self.should_ignore_to(direction)
                )
                if ignore_alerts_from_domain or ignore_alerts_to_domain:



                    return True

        if self.db.is_whitelisted_tranco_domain(domain):


            return True

    def is_part_of_a_whitelisted_org(self, ioc, ioc_type, direction):
        """
        :param ioc: can be ip or domain
        :param direction: can src or dst ip or domain
        :param ioc: can be ip or domain
        """
        is_src = self.is_srcip(direction) or direction in 'srcdomain'
        is_dst = self.is_dstip(direction) or direction in 'dstdomain'

        whitelist = self.db.get_all_whitelist()
        whitelisted_orgs = self.parse_whitelist(whitelist)[2]

        for org in whitelisted_orgs:
            from_ = whitelisted_orgs[org]['from']
            what_to_ignore = whitelisted_orgs[org]['what_to_ignore']
            ignore_alerts = self.should_ignore_alerts(what_to_ignore)
            ignore_alerts_from_org = (
                ignore_alerts
                and is_src
                and self.should_ignore_from(from_)
            )
            ignore_alerts_to_org = (
                ignore_alerts
                and is_dst
                and self.should_ignore_to(from_)
            )


            if ioc_type == 'domain':

                if self.is_domain_in_org(ioc, org):
                    return True

            elif ioc_type == 'ip':
                if ignore_alerts_from_org or ignore_alerts_to_org:

                    self.is_ip_asn_in_org_asn(ioc, org)



                    if self.is_ip_in_org(ioc, org):


                        return True
