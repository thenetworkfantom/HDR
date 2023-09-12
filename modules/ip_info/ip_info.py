from slips_files.common.imports import *
from modules.ip_info.jarm import JARM
from .asn_info import ASN
import platform
import sys
import datetime
import maxminddb
import ipaddress
import whois
import socket
import requests
import json
from contextlib import redirect_stdout, redirect_stderr
import subprocess
import re
import time
import asyncio


class IPInfo(Module, multiprocessing.Process):
    name = 'IP Info'
    description = 'Get different info about an IP/MAC address'
    authors = ['Alya Gomaa', 'Sebastian Garcia']

    def init(self):
        """This will be called when initializing this module"""
        self.pending_mac_queries = multiprocessing.Queue()
        self.asn = ASN(self.db)
        self.JARM = JARM()


        self.c1 = self.db.subscribe('new_ip')
        self.c2 = self.db.subscribe('new_MAC')
        self.c3 = self.db.subscribe('new_dns')
        self.c4 = self.db.subscribe('check_jarm_hash')
        self.channels = {
            'new_ip': self.c1,
            'new_MAC': self.c2,
            'new_dns': self.c3,
            'check_jarm_hash': self.c4,
        }

        self.update_period = 2592000
        self.is_gw_mac_set = False

        self.valid_tlds = [
            '.ac_uk',
            '.am',
            '.amsterdam',
            '.ar',
            '.at',
            '.au',
            '.bank',
            '.be',
            '.biz',
            '.br',
            '.by',
            '.ca',
            '.cc',
            '.cl',
            '.club',
            '.cn',
            '.co',
            '.co_il',
            '.co_jp',
            '.com',
            '.com_au',
            '.com_tr',
            '.cr',
            '.cz',
            '.de',
            '.download',
            '.edu',
            '.education',
            '.eu',
            '.fi',
            '.fm',
            '.fr',
            '.frl',
            '.game',
            '.global_',
            '.hk',
            '.id_',
            '.ie',
            '.im',
            '.in_',
            '.info',
            '.ink',
            '.io',
            '.ir',
            '.is_',
            '.it',
            '.jp',
            '.kr',
            '.kz',
            '.link',
            '.lt',
            '.lv',
            '.me',
            '.mobi',
            '.mu',
            '.mx',
            '.name',
            '.net',
            '.ninja',
            '.nl',
            '.nu',
            '.nyc',
            '.nz',
            '.online',
            '.org',
            '.pe',
            '.pharmacy',
            '.pl',
            '.press',
            '.pro',
            '.pt',
            '.pub',
            '.pw',
            '.rest',
            '.ru',
            '.ru_rf',
            '.rw',
            '.sale',
            '.se',
            '.security',
            '.sh',
            '.site',
            '.space',
            '.store',
            '.tech',
            '.tel',
            '.theatre',
            '.tickets',
            '.trade',
            '.tv',
            '.ua',
            '.uk',
            '.us',
            '.uz',
            '.video',
            '.website',
            '.wiki',
            '.work',
            '.xyz',
            '.za',
        ]

    async def open_dbs(self):
        """Function to open the different offline databases used in this module. ASN, Country etc.."""

        try:
            self.asn_db = maxminddb.open_database(
                'databases/GeoLite2-ASN.mmdb'
            )
        except Exception:
            self.print(
                'Error opening the geolite2 db in databases/GeoLite2-ASN.mmdb. '
                'Please download it from https://dev.maxmind.com/geoip/docs/databases/asn?lang=en '
                'Please note it must be the MaxMind DB version.'
            )


        try:
            self.country_db = maxminddb.open_database(
                'databases/GeoLite2-Country.mmdb'
            )
        except Exception:
            self.print(
                'Error opening the geolite2 db in databases/GeoLite2-Country.mmdb. '
                'Please download it from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data?lang=en. '
                'Please note it must be the MaxMind DB version.'
            )

        asyncio.create_task(self.read_macdb())

    async def read_macdb(self):
        while True:
            try:
                self.mac_db = open('databases/macaddress-db.json', 'r')
                return True
            except OSError:

                try:
                    time.sleep(3)
                except KeyboardInterrupt:
                    return False



    def get_geocountry(self, ip) -> dict:
        """
        Get ip geocountry from geolite database
        :param ip: str
        """
        if not hasattr(self, 'country_db'):
            return False
        if ipaddress.ip_address(ip).is_private:

            data = {'geocountry': 'Private'}
        elif geoinfo := self.country_db.get(ip):
            try:
                countrydata = geoinfo['country']
                countryname = countrydata['names']['en']
                data = {'geocountry': countryname}
            except KeyError:
                data = {'geocountry': 'Unknown'}

        else:
            data = {'geocountry': 'Unknown'}
        self.db.setInfoForIPs(ip, data)
        return data


    def get_ip_family(self, ip):
        """
        returns the family of the IP, AF_INET or AF_INET6
        :param ip: str
        """
        return socket.AF_INET6 if ':' in ip else socket.AF_INET

    def get_rdns(self, ip):
        """
        get reverse DNS of an ip
        returns RDNS of the given ip or False if not found
        :param ip: str
        """
        data = {}
        try:

            reverse_dns = socket.gethostbyaddr(ip)[0]

            try:

                socket.inet_pton(self.get_ip_family(reverse_dns), reverse_dns)
                return False
            except socket.error:

                data['reverse_dns'] = reverse_dns
                self.db.setInfoForIPs(ip, data)
        except (socket.gaierror, socket.herror, OSError):

            return False
        return data



    def get_vendor_online(self, mac_addr):





        url = 'https://api.macvendors.com'
        try:
            response = requests.get(f'{url}/{mac_addr}', timeout=5)
            if response.status_code == 200:


                if vendor:= response.text:
                    return vendor
            return False
        except (
            requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectionError,
            json.decoder.JSONDecodeError,
        ):
            return False

    def get_vendor_offline(self, mac_addr, profileid):
        """
        Gets vendor from Slips' offline database databases/macaddr-db.json
        """
        if not hasattr(self, 'mac_db'):


            self.pending_mac_queries.put((mac_addr, profileid))
            return False

        oui = mac_addr[:8].upper()

        self.mac_db.seek(0)
        while True:
            line = self.mac_db.readline()
            if line == '':


                return False

            if oui in line:
                line = json.loads(line)
                return line['vendorName']

    def get_vendor(self, mac_addr: str, profileid: str):
        """
        Returns vendor info of a MAC address either from an offline or an online
         database
        """

        if (
            'ff:ff:ff:ff:ff:ff' in mac_addr.lower()
            or '00:00:00:00:00:00' in mac_addr.lower()
        ):
            return False


        if self.db.get_mac_vendor_from_profile(profileid):
            return True

        MAC_info = {
            'MAC': mac_addr
        }

        if vendor:= self.get_vendor_offline(mac_addr, profileid):
            MAC_info['Vendor'] = vendor
        elif vendor:= self.get_vendor_online(mac_addr):
            MAC_info['Vendor'] = vendor
        else:
            MAC_info['Vendor'] = 'Unknown'


        self.db.add_mac_addr_to_profile(profileid, MAC_info)
        return MAC_info


    def get_age(self, domain):
        """
        Get the age of a domain using whois library
        """

        if domain.endswith('.arpa') or domain.endswith('.local'):
            return False


        for tld in self.valid_tlds:
            if domain.endswith(tld):

                break
        else:

            return False

        cached_data = self.db.getDomainData(domain)
        if cached_data and 'Age' in cached_data:

            return False




        with open('/dev/null', 'w') as f:
            with redirect_stdout(f) and redirect_stderr(f):

                try:
                    creation_date = whois.query(domain).creation_date
                except Exception:
                    return False

        if not creation_date:

            return False

        today = datetime.datetime.now()

        age = utils.get_time_diff(
            creation_date,
            today,
            return_type='days'
        )

        self.db.setInfoForDomains(domain, {'Age': age})
        return age

    def shutdown_gracefully(self):
        if hasattr(self, 'asn_db'):
            self.asn_db.close()
        if hasattr(self, 'country_db'):
            self.country_db.close()
        if hasattr(self, 'mac_db'):
            self.mac_db.close()


    def get_gateway_ip(self):
        """
        Slips tries different ways to get the ip of the default gateway
        this method tries to get the default gateway IP address using ip route
        only works when running on an interface
        """
        if not ('-i' in sys.argv or self.db.is_growing_zeek_dir()):

            return False

        gw_ip = False
        if platform.system() == 'Darwin':
            route_default_result = subprocess.check_output(
                ['route', 'get', 'default']
            ).decode()
            try:
                gw_ip = re.search(
                    r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}',
                    route_default_result,
                ).group(0)
            except AttributeError:
                pass

        elif platform.system() == 'Linux':
            route_default_result = re.findall(
                r"([\w.][\w.]*'?\w?)",
                subprocess.check_output(['ip', 'route']).decode(),
            )
            gw_ip = route_default_result[2]
        return gw_ip

    def get_gateway_MAC(self, gw_ip: str):
        """
        Given the gw_ip, this function tries to get the MAC
         from arp.log or from arp tables
        """



        if gw_MAC := self.db.get_mac_addr_from_profile(f'profile_{gw_ip}'):
            self.db.set_default_gateway('MAC', gw_MAC)
            return gw_MAC


        running_on_interface = '-i' in sys.argv or self.db.is_growing_zeek_dir()
        if not running_on_interface:



            return



        try:
            ip_output = subprocess.run(["ip", "neigh", "show", gw_ip],
                                      capture_output=True, check=True, text=True).stdout
            gw_MAC = ip_output.split()[-2]
            self.db.set_default_gateway('MAC', gw_MAC)
            return gw_MAC
        except (subprocess.CalledProcessError, FileNotFoundError):

            try:
                arp_output = subprocess.run(["arp", "-an"],
                                           capture_output=True, check=True, text=True).stdout
                for line in arp_output.split('\n'):
                    fields = line.split()
                    gw_ip_from_arp_cmd = fields[1].strip('()')

                    if len(fields) >= 2 and gw_ip_from_arp_cmd == gw_ip:
                        gw_MAC = fields[-4]
                        self.db.set_default_gateway('MAC', gw_MAC)
                        return gw_MAC
            except (subprocess.CalledProcessError, FileNotFoundError):

                return

        return gw_MAC

    def check_if_we_have_pending_mac_queries(self):
        """
        Checks if we have pending queries in pending_mac_queries queue, and asks the db for them IF
        update manager is done updating the mac db
        """
        if hasattr(self, 'mac_db') and not self.pending_mac_queries.empty():
            while True:
                try:
                    mac, profileid = self.pending_mac_queries.get(timeout=0.5)
                    self.get_vendor(mac, profileid)

                except Exception:

                    return

    def wait_for_dbs(self):
        """
        wait for update manager to finish updating the mac db and open the rest of dbs before starting this module
        """

        loop = asyncio.get_event_loop()


        loop.run_until_complete(self.open_dbs())

    def set_evidence_malicious_jarm_hash(
            self,
            flow,
            uid,
            profileid,
            twid,
    ):
        dport = flow['dport']
        dstip = flow['daddr']
        timestamp = flow['starttime']
        protocol = flow['proto']

        evidence_type = 'MaliciousJARM'
        attacker_direction = 'dstip'
        source_target_tag = 'Malware'
        attacker = dstip
        threat_level = 'medium'
        confidence = 0.7
        category = 'Anomaly.Traffic'
        portproto = f'{dport}/{protocol}'
        port_info = self.db.get_port_info(portproto)
        port_info = port_info or ""
        port_info = f'({port_info.upper()})' if port_info else ""
        dstip_id = self.db.get_ip_identification(dstip)
        description = (
           f"Malicious JARM hash detected for destination IP: {dstip}"
           f" on port: {portproto} {port_info}.  {dstip_id}"
        )

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag,
                                 port=dport, proto=protocol, profileid=profileid, twid=twid, uid=uid)

    def pre_main(self):
        utils.drop_root_privs()
        self.wait_for_dbs()

        if ip := self.get_gateway_ip():
            self.db.set_default_gateway('IP', ip)

    def handle_new_ip(self, ip):
        try:

            ip_addr = ipaddress.ip_address(ip)
        except ValueError:

            return

        if not ip_addr.is_multicast:


            cached_ip_info = self.db.getIPData(ip)
            if not cached_ip_info:
                cached_ip_info = {}



            if (
                    cached_ip_info == {}
                    or 'geocountry' not in cached_ip_info
            ):
                self.get_geocountry(ip)





            if update_asn := self.asn.update_asn(
                    cached_ip_info,
                    self.update_period
            ):
                self.asn.get_asn(ip, cached_ip_info)
            self.get_rdns(ip)

    def main(self):
        if msg:= self.get_msg('new_MAC'):
            data = json.loads(msg['data'])
            mac_addr = data['MAC']
            host_name = data.get('host_name', False)
            profileid = data['profileid']

            if host_name:
                self.db.add_host_name_to_profile(host_name, profileid)

            self.get_vendor(mac_addr, profileid)
            self.check_if_we_have_pending_mac_queries()

            if not self.is_gw_mac_set:



                if ip:= self.db.get_gateway_ip():


                    self.get_gateway_MAC(ip)
                    self.is_gw_mac_set = True

        if msg:= self.get_msg('new_dns'):
            data = msg['data']
            data = json.loads(data)



            flow_data = json.loads(
                data['flow']
            )
            if domain := flow_data.get('query', False):
                self.get_age(domain)

        if msg:= self.get_msg('new_ip'):

            ip = msg['data']
            self.handle_new_ip(ip)

