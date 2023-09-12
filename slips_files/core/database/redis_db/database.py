from slips_files.common.slips_utils import utils
from slips_files.common.config_parser import ConfigParser
from slips_files.core.database.sqlite_db.database import SQLiteDB
from slips_files.core.database.redis_db.ioc_handler import IoCHandler
from slips_files.core.database.redis_db.alert_handler import AlertHandler
from slips_files.core.database.redis_db.profile_handler import ProfileHandler

import os
import signal
import redis
import time
import json
import subprocess
from datetime import datetime
import ipaddress
import sys
import validators

RUNNING_IN_DOCKER = os.environ.get('IS_IN_A_DOCKER_CONTAINER', False)


class RedisDB(IoCHandler, AlertHandler, ProfileHandler):
    """Main redis db class."""


    _obj = None
    _port = None

    _instances = {}

    supported_channels = {
        'tw_modified',
        'evidence_added',
        'new_ip',
        'new_flow',
        'new_dns',
        'new_dns_flow',
        'new_http',
        'new_ssl',
        'new_profile',
        'give_threat_intelligence',
        'new_letters',
        'ip_info_change',
        'dns_info_change',
        'dns_info_change',
        'tw_closed',
        'core_messages',
        'new_blocking',
        'new_ssh',
        'new_notice',
        'new_url',
        'new_downloaded_file',
        'reload_whitelist',
        'new_service',
        'new_arp',
        'new_MAC',
        'new_smtp',
        'new_blame',
        'new_alert',
        'new_dhcp',
        'new_weird',
        'new_software',
        'p2p_data_request',
        'remove_old_files',
        'export_evidence',
        'p2p_data_request',
        'p2p_gopy',
        'report_to_peers',
        'new_tunnel',
        'check_jarm_hash',
        'control_channel',
        'new_module_flow'
        }

    name = 'DB'
    separator = '_'
    normal_label = 'benign'
    malicious_label = 'malicious'
    sudo = 'sudo '
    if RUNNING_IN_DOCKER:
        sudo = ''

    _gateway_MAC_found = False
    _conf_file = 'config/redis.conf'
    our_ips = utils.get_own_IPs()

    first_flow = True

    is_localnet_set = False

    def __new__(cls, redis_port, output_queue, flush_db=True):
        """
        treat the db as a singelton per port
        meaning every port will have exactly 1 single obj of this db at any given time
        """
        cls.redis_port, cls.outputqueue = redis_port, output_queue
        cls.flush_db = flush_db
        if cls.redis_port not in cls._instances:
            cls._instances[cls.redis_port] = super().__new__(cls)
            cls._set_redis_options()
            cls._read_configuration()
            cls.start()

            cls.set_slips_internal_time(0)
            if not cls.get_slips_start_time():
                cls._set_slips_start_time()

            cls.r.client_setname(f"Slips-DB")

        return cls._instances[cls.redis_port]

    @classmethod
    def _set_redis_options(cls):
        """
        Sets the default slips options,
         when using a different port we override it with -p
        """
        cls._options = {
                'daemonize': 'yes',
                'stop-writes-on-bgsave-error': 'no',
                'save': '""',
                'appendonly': 'no'
            }

        if '-s' in sys.argv:







            cls._options.update({
                'save': '30 500',
                'appendonly': 'yes',
                'dir': os.getcwd(),
                'dbfilename': 'dump.rdb',
                })

        with open(cls._conf_file, 'w') as f:
            for option, val in cls._options.items():
                f.write(f'{option} {val}\n')

    @classmethod
    def _read_configuration(cls):
        conf = ConfigParser()
        cls.deletePrevdb = conf.deletePrevdb()
        cls.disabled_detections = conf.disabled_detections()
        cls.home_network = conf.get_home_network()
        cls.width = conf.get_tw_width_as_float()

    @classmethod
    def set_slips_internal_time(cls, timestamp):
        cls.r.set('slips_internal_time', timestamp)

    @classmethod
    def get_slips_start_time(cls):
        """get the time slips started (datetime obj)"""
        if start_time := cls.r.get('slips_start_time'):
            start_time = utils.convert_format(start_time, utils.alerts_format)
            return start_time

    @classmethod
    def start(cls):
        """Flushes and Starts the DB and """
        try:
            cls.connect_to_redis_server()






            if (
                    cls.deletePrevdb
                    and not ('-S' in sys.argv or '-cb' in sys.argv or '-d' in sys.argv )
                    and cls.flush_db
            ):


                cls.r.flushdb()

            cls.change_redis_limits(cls.r)
            cls.change_redis_limits(cls.rcache)




            cls.r.delete('zeekfiles')

        except redis.exceptions.ConnectionError as ex:
            print(f"[DB] Can't connect to redis on port {cls.redis_port}: {ex}")
            return False

    @classmethod
    def connect_to_redis_server(cls):
        """Connects to the given port and Sets r and rcache"""

        os.system(
            f'redis-server {cls._conf_file} --port {cls.redis_port}  > /dev/null 2>&1'
        )
        try:
            cls.r = redis.StrictRedis(
                host='localhost',
                port=cls.redis_port,
                db=0,
                charset='utf-8',
                socket_keepalive=True,
                decode_responses=True,
                retry_on_timeout=True,
                health_check_interval=20,
            )

            cls.rcache = redis.StrictRedis(
                host='localhost',
                port=6379,
                db=1,
                charset='utf-8',
                socket_keepalive=True,
                retry_on_timeout=True,
                decode_responses=True,
                health_check_interval=30,
            )




            time.sleep(1)
            cls.r.client_list()
            return True
        except redis.exceptions.ConnectionError:




            if cls.redis_port != 32850:



                cls.close_redis_server(cls.redis_port)

            return False

    @classmethod
    def close_redis_server(cls, redis_port):
        if server_pid := cls.get_redis_server_PID(redis_port):
            os.kill(int(server_pid), signal.SIGKILL)

    @classmethod
    def change_redis_limits(cls, client):
        """
        To fix redis closing/resetting the pub/sub connection, change redis soft and hard limits
        """







        client.config_set('client-output-buffer-limit', "normal 0 0 0 "
                                                        "slave 268435456 67108864 60 "
                                                        "pubsub 4294967296 2147483648 600")

    @classmethod
    def _set_slips_start_time(cls):
        """store the time slips started (datetime obj)"""
        now = utils.convert_format(datetime.now(), utils.alerts_format)
        cls.r.set('slips_start_time', now)

    def publish(self, channel, data):
        """Publish something"""
        self.r.publish(channel, data)

    def subscribe(self, channel: str, ignore_subscribe_messages=True):
        """Subscribe to channel"""

        if channel not in self.supported_channels:
            return False

        self.pubsub = self.r.pubsub()
        self.pubsub.subscribe(
            channel, ignore_subscribe_messages=ignore_subscribe_messages
            )
        return self.pubsub

    def publish_stop(self):
        """
        Publish stop command to terminate slips
        to shutdown slips gracefully, this function should only be used by slips.py
        """
        self.print('Sending the stop signal to all listeners', 0, 3)
        self.r.publish('control_channel', 'stop_slips')

    def get_message(self, channel, timeout=0.0000001):
        """
        Wrapper for redis' get_message() to be able to handle redis.exceptions.ConnectionError
        notice: there has to be a timeout or the channel will wait forever and never receive a new msg
        """
        try:
            return channel.get_message(timeout=timeout)
        except redis.exceptions.ConnectionError as ex:
            if not self.is_connection_error_logged():
                self.publish_stop()
                self.print(f'Stopping slips due to redis.exceptions.ConnectionError: {ex}', 0, 1)

                self.mark_connection_error_as_logged()

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
        try:
            self.outputqueue.put(f'{levels}|{self.name}|{text}')
        except AttributeError:
            pass

    def getIPData(self, ip: str) -> dict:
        """
        Return information about this IP from IPsInfo
        Returns a dictionary or False if there is no IP in the database
        We need to separate these three cases:
        1- IP is in the DB without data. Return empty dict.
        2- IP is in the DB with data. Return dict.
        3- IP is not in the DB. Return False
        """

        data = self.rcache.hget('IPsInfo', ip)
        return json.loads(data) if data else False

    def set_new_ip(self, ip: str):
        """
        1- Stores this new IP in the IPs hash
        2- Publishes in the channels that there is a new IP, and that we want
            data from the Threat Intelligence modules
        Sometimes it can happend that the ip comes as an IP object, but when
        accessed as str, it is automatically
        converted to str
        """
        data = self.getIPData(ip)
        if data is False:





            self.rcache.hset('IPsInfo', ip, '{}')

            self.publish('new_ip', ip)

    def ask_for_ip_info(self, ip, profileid, twid, proto, starttime, uid, ip_state, daddr=False):
        """
        is the ip param src or dst
        """

        daddr = daddr or ip
        data_to_send = self.give_threat_intelligence(
            profileid,
            twid,
            ip_state,
            starttime,
            uid,
            daddr,
            proto=proto,
            lookup=ip
        )

        if ip in self.our_ips:

            return


        cache_age = 1000

        data_to_send.update({
            'cache_age': cache_age,
            'ip': str(ip)
        })
        self.publish('p2p_data_request', json.dumps(data_to_send))

    def update_times_contacted(self, ip, direction, profileid, twid):
        """
        :param ip: the ip that we want to update the times we contacted
        """


        profileid_twid = f'{profileid}{self.separator}{twid}'



        ips_contacted = self.r.hget(profileid_twid, f'{direction}IPs')
        if not ips_contacted:
            ips_contacted = {}

        try:
            ips_contacted = json.loads(ips_contacted)

            ips_contacted[ip] += 1
        except (TypeError, KeyError):

            ips_contacted[ip] = 1

        ips_contacted = json.dumps(ips_contacted)
        self.r.hset(profileid_twid, f'{direction}IPs', str(ips_contacted))


    def update_ip_info(
        self,
        old_profileid_twid_data,
        pkts,
        dport,
        spkts,
        totbytes,
        ip,
        starttime,
        uid
    ):
        """

        the total flows sent by this ip and their uids,
        the total packets sent by this ip,
        total bytes sent by this ip
        """
        dport = str(dport)
        spkts = int(spkts)
        pkts = int(pkts)
        totbytes = int(totbytes)

        try:

            ip_data = old_profileid_twid_data[ip]
            ip_data['totalflows'] += 1
            ip_data['totalpkt'] += pkts
            ip_data['totalbytes'] += totbytes
            ip_data['uid'].append(uid)
            if dport in ip_data['dstports']:
                ip_data['dstports'][dport] += spkts
            else:
                ip_data['dstports'][dport] = spkts

        except KeyError:

            ip_data = {
                'totalflows': 1,
                'totalpkt': pkts,
                'totalbytes': totbytes,
                'stime': starttime,
                'uid': [uid],
                'dstports': {dport: spkts}

            }

        old_profileid_twid_data[ip] = ip_data
        return old_profileid_twid_data

    def getSlipsInternalTime(self):
        return self.r.get('slips_internal_time')

    def get_redis_keys_len(self) -> int:
        """returns the length of all keys in the db"""
        return self.r.dbsize()

    def set_cyst_enabled(self):
        return self.r.set('is_cyst_enabled', 'yes')

    def is_cyst_enabled(self):
        return self.r.get('is_cyst_enabled')


    def get_equivalent_tws(self, hrs: float):
        """
        How many tws correspond to the given hours?
        for example if the tw width is 1h, and hrs is 24, this function returns 24
        """
        return int(hrs*3600/self.width)

    def set_local_network(self, saddr):

        if self.is_localnet_set:
            return

        if saddr in ('0.0.0.0', '255.255.255.255'):
            return

        if not (
                validators.ipv4(saddr)
                and ipaddress.ip_address(saddr).is_private
        ):
            return

        if network_range := utils.get_cidr_of_ip(saddr):
            self.r.set("local_network", network_range)
            self.is_localnet_set = True

    def get_used_port(self):
        return int(self.r.config_get('port')['port'])

    def get_local_network(self):
         return self.r.get("local_network")

    def get_label_count(self, label):
        """
        :param label: malicious or normal
        """
        return self.r.zscore('labels', label)

    def get_disabled_modules(self) -> list:
        if disabled_modules := self.r.hget('analysis', 'disabled_modules'):
            return json.loads(disabled_modules)
        else:
            return {}

    def set_input_metadata(self, info:dict):
        """
        sets name, size, analysis dates, and zeek_dir in the db
        """
        for info, val in info.items():
            self.r.hset('analysis', info, val)

    def get_zeek_output_dir(self):
        """
        gets zeek output dir from the db
        """
        return self.r.hget('analysis', 'zeek_dir')

    def get_input_file(self):
        """
        gets zeek output dir from the db
        """
        return self.r.hget('analysis', 'name')

    def get_commit(self):
        """
        gets the currently used commit from the db
        """
        return self.r.hget('analysis', 'commit')

    def get_branch(self):
        """
        gets the currently used branch from the db
        """
        return self.r.hget('analysis', 'branch')

    def get_evidence_detection_threshold(self):
        """
        gets the currently used evidence_detection_threshold from the db
        """
        return self.r.hget('analysis', 'evidence_detection_threshold')


    def get_input_type(self):
        """
        gets input type from the db
        """
        return self.r.hget('analysis', 'input_type')

    def get_output_dir(self):
        """
        returns the currently used output dir
        """
        return self.r.hget('analysis', 'output_dir')

    def setInfoForIPs(self, ip: str, to_store: dict):
        """
        Store information for this IP
        We receive a dictionary, such as {'geocountry': 'rumania'} that we are
        going to store for this IP.
        If it was not there before we store it. If it was there before, we
        overwrite it
        """

        cached_ip_info = self.getIPData(ip)
        if cached_ip_info is False:

            self.set_new_ip(ip)
            cached_ip_info = {}


        is_new_info = False
        for info_type, info_val in to_store.items():
            if (
                    info_type not in cached_ip_info
                    and not is_new_info
            ):
                is_new_info = True

            cached_ip_info[info_type] = info_val

        self.rcache.hset('IPsInfo', ip, json.dumps(cached_ip_info))
        if is_new_info:
            self.r.publish('ip_info_change', ip)

    def get_redis_pid(self):
        """returns the pid of the current redis server"""
        return int(self.r.info()['process_id'])

    def get_p2p_reports_about_ip(self, ip) -> dict:
        """
        returns a dict of all p2p past reports about the given ip
        """

        if reports := self.rcache.hget('p2p_reports', ip):
            return json.loads(reports)
        return {}

    def store_p2p_report(self, ip: str, report_data: dict):
        """
        stores answers about IPs slips asked other peers for.
        """

        reporter = report_data['reporter']
        del report_data['reporter']



        if cached_p2p_reports := self.get_p2p_reports_about_ip(ip):

            if reporter in cached_p2p_reports:


                last_report_about_this_ip = cached_p2p_reports[reporter][-1]
                score = report_data['score']
                confidence = report_data['confidence']
                if (
                        last_report_about_this_ip['score'] == score
                        and last_report_about_this_ip['confidence'] == confidence
                ):
                    report_time = report_data['report_time']

                    last_report_about_this_ip['report_time'] = report_time
                else:

                    cached_p2p_reports[reporter].append(report_data)
            else:

                cached_p2p_reports[reporter] = [report_data]
            report_data = cached_p2p_reports
        else:

            report_data = {reporter: [report_data]}

        self.rcache.hset('p2p_reports', ip, json.dumps(report_data))


    def get_dns_resolution(self, ip):
        """
        IF this IP was resolved by slips
        returns a dict with {ts: .. ,
                            'domains': .. ,
                            'uid':...,
                            'resolved-by':.. }
        If not resolved, returns {}
        this function is called for every IP in the timeline of kalipso
        """
        if ip_info := self.r.hget('DNSresolution', ip):
            ip_info = json.loads(ip_info)

            return ip_info
        return {}

    def is_ip_resolved(self, ip, hrs):
        """
        :param hrs: float, how many hours to look back for resolutions
        """
        ip_info = self.get_dns_resolution(ip)
        if ip_info == {}:
            return False


        tws = ip_info['timewindows']


        tws_to_search = self.get_equivalent_tws(hrs)

        current_twid = 0
        while tws_to_search != current_twid:
            matching_tws = [i for i in tws if f'timewindow{current_twid}' in i]

            if not matching_tws:
                current_twid += 1
            else:
                return True

    def delete_dns_resolution(self , ip):
        self.r.hdel("DNSresolution" , ip)

    def should_store_resolution(self, query: str, answers: list, qtype_name: str):


        if (
                qtype_name not in ['AAAA', 'A']
                or answers == '-'
                or query.endswith('arpa')
        ):
            return False



        if query != 'localhost':
            for answer in answers:
                if answer in ("127.0.0.1" , "0.0.0.0"):
                    return False

        return True

    def set_dns_resolution(
        self,
        query: str,
        answers: list,
        ts: float,
        uid: str,
        qtype_name: str,
        srcip: str,
        twid: str,
    ):
        """
        Cache DNS answers
        1- For each ip in the answer, store the domain
           in DNSresolution as {ip: {ts: .. , 'domains': .. , 'uid':... }}
        2- For each CNAME, store the ip

        :param srcip: ip that performed the dns query
        """
        if not self.should_store_resolution(query, answers, qtype_name):
            return

        ips_to_add = []
        CNAMEs = []
        profileid_twid = f'profile_{srcip}_{twid}'

        for answer in answers:

            if not validators.ipv6(answer) and not validators.ipv4(answer):
                if 'TXT' in answer:
                    continue


                CNAMEs.append(answer)
                continue



            ip_info_from_db = self.get_dns_resolution(answer)
            if ip_info_from_db == {}:

                resolved_by = [srcip]
                domains = []
                timewindows = [profileid_twid]
            else:


                resolved_by = ip_info_from_db.get('resolved-by', [])
                if srcip not in resolved_by:
                    resolved_by.append(srcip)


                timewindows = ip_info_from_db.get('timewindows', [])
                if profileid_twid not in timewindows:
                    timewindows.append(profileid_twid)


                domains = ip_info_from_db.get('domains', [])


            if query not in domains:
                domains.append(query)


            ip_info = {
                'ts': ts,
                'uid': uid,
                'domains': domains,
                'resolved-by': resolved_by,
                'timewindows': timewindows,
            }
            ip_info = json.dumps(ip_info)


            self.r.hset('DNSresolution', answer, ip_info)

            self.r.hset('ResolvedDomains', domains[0], answer)

            ips_to_add.append(answer)




        if ips_to_add:
            domaindata = {'IPs': ips_to_add}

            try:

                domaindata['CNAME'] = CNAMEs
            except NameError:

                pass

            self.setInfoForDomains(query, domaindata, mode='add')
            self.set_domain_resolution(query, ips_to_add)

    def set_domain_resolution(self, domain, ips):
        """
        stores all the resolved domains with their ips in the db
        """
        self.r.hset("DomainsResolved", domain, json.dumps(ips))


    @staticmethod
    def get_redis_server_PID(redis_port):
        """
        get the PID of the redis server started on the given redis_port
        retrns the pid
        """
        cmd = 'ps aux | grep redis-server'
        cmd_output = os.popen(cmd).read()
        for line in cmd_output.splitlines():
            if str(redis_port) in line:
                pid = line.split()[1]
                return pid
        return False



    def set_slips_mode(self, slips_mode):
        """
        function to store the current mode (daemonized/interactive)
        in the db
        """
        self.r.set("mode", slips_mode)

    def get_slips_mode(self):
        """
        function to get the current mode (daemonized/interactive)
        in the db
        """
        self.r.get("mode")

    def get_modified_ips_in_the_last_tw(self):
        """
        this number is updated in the db every 5s by slips.py
        used for printing running stats in slips.py or outputprocess
        """
        if modified_ips := self.r.hget('analysis', 'modified_ips_in_the_last_tw'):
            return modified_ips
        else:
            return 0

    def is_connection_error_logged(self):
        return bool(self.r.get('logged_connection_error'))

    def mark_connection_error_as_logged(self):
        """
        When redis connection error occurs, to prevent every module from logging it to slips.log and the console,
        set this variable in the db
        """
        self.r.set('logged_connection_error', 'True')


    def was_ip_seen_in_connlog_before(self, ip) -> bool:
        """
        returns true if this is not the first flow slip sees of the given ip
        """





        return self.r.sismember("srcips_seen_in_connlog", ip)

    def mark_srcip_as_seen_in_connlog(self, ip):
        """
        Marks the given ip as seen in conn.log
        if an ip is not present in this set, it means we may have seen it but not in conn.log
        """
        self.r.sadd("srcips_seen_in_connlog", ip)

    def is_gw_mac(self, MAC_info, ip) -> bool:
        """
        Detects the MAC of the gateway if 1 mac is seen assigned to 1 public destination IP
        :param ip: dst ip that should be associated with the given MAC info
        """

        MAC = MAC_info.get('MAC', '')
        if not validators.mac_address(MAC):
            return False

        if self._gateway_MAC_found:

            return self.get_gateway_mac() == MAC


        ip_obj = ipaddress.ip_address(ip)
        if not ip_obj.is_private:




            for address_type, address in MAC_info.items():

                self.set_default_gateway(address_type, address)


            self._gateway_MAC_found = True
            return True

    def get_ip_of_mac(self, MAC):
        """
        Returns the IP associated with the given MAC in our database
        """
        return self.r.hget('MAC', MAC)

    def get_modified_tw(self):
        """Return all the list of modified tw"""
        data = self.r.zrange('ModifiedTW', 0, -1, withscores=True)
        return data or []

    def get_field_separator(self):
        """Return the field separator"""
        return self.separator

    def store_tranco_whitelisted_domain(self, domain):
        """
        store whitelisted domain from tranco whitelist in the db
        """


        self.rcache.sadd('tranco_whitelisted_domains', domain)

    def is_whitelisted_tranco_domain(self, domain):
        return self.rcache.sismember('tranco_whitelisted_domains', domain)

    def set_growing_zeek_dir(self):
        """
        Mark a dir as growing so it can be treated like the zeek logs generated by an interface
        """
        self.r.set('growing_zeek_dir', 'yes')

    def is_growing_zeek_dir(self):
        """ Did slips mark the given dir as growing?"""
        return 'yes' in str(self.r.get('growing_zeek_dir'))

    def get_ip_identification(self, ip: str, get_ti_data=True):
        """
        Return the identification of this IP based
        on the data stored so far
        :param get_ti_data: do we want to get info about this IP from out TI lists?
        """
        current_data = self.getIPData(ip)
        identification = ''
        if current_data:
            if 'asn' in current_data:
                asn_details = ''
                if asnorg := current_data['asn'].get('org', ''):
                    asn_details += f'{asnorg} '

                if number := current_data['asn'].get('number', ''):
                    asn_details += f'{number} '

                if len(asn_details) > 1:
                    identification += f'AS: {asn_details}'

            if 'SNI' in current_data:
                sni = current_data['SNI']
                if type(sni) == list:
                    sni = sni[0]
                identification += 'SNI: ' + sni['server_name'] + ', '

            if 'reverse_dns' in current_data:
                identification += 'rDNS: ' + current_data['reverse_dns'] + ', '

            if 'threatintelligence' in current_data and get_ti_data:
                identification += (
                    'Description: '
                    + current_data['threatintelligence']['description']
                    + ', '
                    )

                tags: list = current_data['threatintelligence'].get('tags', False)

                if tags:
                    identification += f'tags= {tags}  '

        identification = identification[:-2]
        return identification

    def get_multiaddr(self):
        """
        this is can only be called when p2p is enabled, this value is set by p2p pigeon
        """
        return self.r.get('multiAddress')

    def get_labels(self):
        """
        Return the amount of each label so far in the DB
        Used to know how many labels are available during training
        """
        return self.r.zrange('labels', 0, -1, withscores=True)

    def set_port_info(self, portproto: str, name):
        """
        Save in the DB a port with its description
        :param portproto: portnumber + / + protocol
        """
        self.rcache.hset('portinfo', portproto, name)

    def get_port_info(self, portproto: str):
        """
        Retrieve the name of a port
        :param portproto: portnumber + / + protocol
        """
        return self.rcache.hget('portinfo', portproto)

    def set_ftp_port(self, port):
        """
        Stores the used ftp port in our main db (not the cache like set_port_info)
        """
        self.r.lpush('used_ftp_ports', str(port))

    def is_ftp_port(self, port):

        used_ftp_ports = self.r.lrange('used_ftp_ports', 0, -1)

        return str(port) in used_ftp_ports

    def set_organization_of_port(self, organization, ip: str, portproto: str):
        """
        Save in the DB a port with its organization and the ip/ range used by this organization
        :param portproto: portnumber + / + protocol.lower()
        :param ip: can be a single org ip, or a range or ''
        """
        if org_info := self.get_organization_of_port(portproto):

            org_info = json.loads(org_info)
            org_info['ip'].append(ip)
            org_info['org_name'].append(organization)
        else:
            org_info = {'org_name': [organization], 'ip': [ip]}

        org_info = json.dumps(org_info)
        self.rcache.hset('organization_port', portproto, org_info)

    def get_organization_of_port(self, portproto: str):
        """
        Retrieve the organization info that uses this port
        :param portproto: portnumber.lower() + / + protocol
        """


        return self.rcache.hget('organization_port', portproto.lower())

    def add_zeek_file(self, filename):
        """Add an entry to the list of zeek files"""
        self.r.sadd('zeekfiles', filename)

    def get_all_zeek_file(self):
        """Return all entries from the list of zeek files"""
        return self.r.smembers('zeekfiles')

    def get_gateway_ip(self):
        return self.r.hget('default_gateway', 'IP')

    def get_gateway_mac(self):
        return self.r.hget('default_gateway', 'MAC')

    def get_gateway_MAC_Vendor(self):
        return self.r.hget('default_gateway', 'Vendor')

    def set_default_gateway(self, address_type:str, address:str):
        """
        :param address_type: can either be 'IP' or 'MAC'
        :param address: can be ip or mac
        """

        if (
                (address_type == 'IP' and not self.get_gateway_ip())
                or (address_type == 'MAC' and not self.get_gateway_mac())
                or (address_type == 'Vendor' and not self.get_gateway_MAC_Vendor())
        ):
            self.r.hset('default_gateway', address_type, address)


    def get_domain_resolution(self, domain):
        """
        Returns the IPs resolved by this domain
        """
        ips = self.r.hget("DomainsResolved", domain)
        return json.loads(ips) if ips else []

    def get_all_dns_resolutions(self):
        dns_resolutions = self.r.hgetall('DNSresolution')
        return dns_resolutions or []

    def set_passive_dns(self, ip, data):
        """
        Save in DB passive DNS from virus total
        """
        if data:
            data = json.dumps(data)
            self.rcache.hset('passiveDNS', ip, data)

    def get_passive_dns(self, ip):
        """
        Gets passive DNS from the db
        """
        if data := self.rcache.hget('passiveDNS', ip):
            return json.loads(data)
        else:
            return False

    def get_reconnections_for_tw(self, profileid, twid):
        """Get the reconnections for this TW for this Profile"""
        if not profileid:


            return False
        data = self.r.hget(profileid + self.separator + twid, 'Reconnections')
        data = json.loads(data) if data else {}
        return data

    def setReconnections(self, profileid, twid, data):
        """Set the reconnections for this TW for this Profile"""
        data = json.dumps(data)
        self.r.hset(
            profileid + self.separator + twid, 'Reconnections', str(data)
        )

    def get_host_ip(self):
        """Get the IP addresses of the host from a db. There can be more than one"""
        return self.r.smembers('hostIP')

    def set_host_ip(self, ip):
        """Store the IP address of the host in a db. There can be more than one"""
        self.r.sadd('hostIP', ip)


    def set_asn_cache(self, org: str, asn_range: str, asn_number: str) -> None:
        """
        Stores the range of asn in cached_asn hash
        """

        range_info = {
            asn_range: {
                'org': org
            }
        }
        if asn_number:
            range_info[asn_range].update(
                {'number': f'AS{asn_number}'}
            )

        first_octet = utils.get_first_octet(asn_range)
        if not first_octet:
            return


        """
        {
            '192' : {
                '192.168.1.0/x': {'number': 'AS123', 'org':'Test'},
                '192.168.1.0/x': {'number': 'AS123', 'org':'Test'},
            },
            '10': {
                '10.0.0.0/x': {'number': 'AS123', 'org':'Test'},
            }

        }
        """
        if cached_asn := self.get_asn_cache(first_octet=first_octet):

            cached_asn: dict = json.loads(cached_asn)
            cached_asn.update(range_info)
            self.rcache.hset('cached_asn', first_octet, json.dumps(cached_asn))
        else:

            self.rcache.hset('cached_asn', first_octet, json.dumps(range_info))

    def get_asn_cache(self, first_octet=False):
        """
         cached ASNs are sorted by first octet
        Returns cached asn of ip if present, or False.
        """
        if first_octet:
            return self.rcache.hget('cached_asn', first_octet)
        else:
            return self.rcache.hgetall('cached_asn')

    def store_process_PID(self, process, pid):
        """
        Stores each started process or module with it's PID
        :param pid: int
        :param process: str
        """
        self.r.hset('PIDs', process, pid)

    def get_pids(self) -> dict:
        """returns a dict with module names as keys and PIDs as values"""
        return self.r.hgetall('PIDs')

    def get_pid_of(self, module_name: str):
        pid = self.r.hget('PIDs', module_name)
        return int(pid) if pid else None

    def get_name_of_module_at(self, given_pid):
        """returns the name of the module that has the given pid """
        for name, pid in self.get_pids().items():
            if int(given_pid) == int(pid):
                return name


    def set_org_info(self, org, org_info, info_type):
        """
        store ASN, IP and domains of an org in the db
        :param org: supported orgs are ('google', 'microsoft', 'apple', 'facebook', 'twitter')
        : param org_info: a json serialized list of asns or ips or domains
        :param info_type: supported types are 'asn', 'domains', 'IPs'
        """

        self.rcache.hset('OrgInfo', f'{org}_{info_type}', org_info)

    def get_org_info(self, org, info_type) -> str:
        """
        get the ASN, IP and domains of an org from the db
        :param org: supported orgs are ('google', 'microsoft', 'apple', 'facebook', 'twitter')
        :param info_type: supported types are 'asn', 'domains'
        " returns a json serialized dict with info
        """
        return self.rcache.hget('OrgInfo', f'{org}_{info_type}') or '[]'

    def get_org_IPs(self, org):
        org_info = self.rcache.hget('OrgInfo', f'{org}_IPs')

        if not org_info:
            org_info = {}
            return org_info

        try:
            return json.loads(org_info)
        except TypeError:

            return org_info

    def set_whitelist(self, type_, whitelist_dict):
        """
        Store the whitelist_dict in the given key
        :param type_: supporte types are IPs, domains and organizations
        :param whitelist_dict: the dict of IPs, domains or orgs to store
        """
        self.r.hset('whitelist', type_, json.dumps(whitelist_dict))

    def get_all_whitelist(self):
        """Return dict of 3 keys: IPs, domains, organizations or mac"""
        return self.r.hgetall('whitelist')

    def get_whitelist(self, key):
        """
        Whitelist supports different keys like : IPs domains and organizations
        this function is used to check if we have any of the above keys whitelisted
        """
        if whitelist := self.r.hget('whitelist', key):
            return json.loads(whitelist)
        else:
            return {}

    def store_dhcp_server(self, server_addr):
        """
        Store all seen DHCP servers in the database.
        """

        try:
            ipaddress.ip_address(server_addr)
        except ValueError:

            return False

        dhcp_servers = self.r.lrange('DHCP_servers', 0, -1)
        if server_addr not in dhcp_servers:
            self.r.lpush('DHCP_servers', server_addr)

    def save(self, backup_file):
        """
        Save the db to disk.
        backup_file should be the path+name of the file you want to save the db in
        If you -s the same file twice the old backup will be overwritten.
        """






        self.r.save()


        redis_db_path = os.path.join(os.getcwd(), 'dump.rdb')

        if os.path.exists(redis_db_path):
            command = f'{self.sudo} cp {redis_db_path} {backup_file}.rdb'
            os.system(command)
            os.remove(redis_db_path)
            print(f'[Main] Database saved to {backup_file}.rdb')
            return True

        print(
            f'[DB] Error Saving: Cannot find the redis database directory {redis_db_path}'
        )
        return False

    def load(self, backup_file: str) -> bool:
        """
        Load the db from disk to the db on port 32850
        backup_file should be the full path of the .rdb
        """

        def is_valid_rdb_file():
            if not os.path.exists(backup_file):
                print("{} doesn't exist.".format(backup_file))
                return False


            command = f'file {backup_file}'
            result = subprocess.run(command.split(), stdout=subprocess.PIPE)
            file_type = result.stdout.decode('utf-8')
            if 'Redis' not in file_type:
                print(
                    f'{backup_file} is not a valid redis database file.'
                )
                return False
            return True

        if not is_valid_rdb_file():
            return False

        try:
            RedisDB._options.update({
                'dbfilename': os.path.basename(backup_file),
                'dir': os.path.dirname(backup_file),
                'port': 32850,
            })

            with open(RedisDB._conf_file, 'w') as f:
                for option, val in RedisDB._options.items():
                    f.write(f'{option} {val}\n')

            os.system(f'{self.sudo}service redis-server stop')


            os.system('redis-server redis.conf > /dev/null 2>&1')
            return True
        except Exception:
            self.print(
                f'Error loading the database {backup_file}.'
            )
            return False

    def set_last_warden_poll_time(self, time):
        """
        :param time: epoch
        """
        self.r.hset('Warden', 'poll', time)

    def get_last_warden_poll_time(self):
        """
        returns epoch time of last poll
        """
        time = self.r.hget('Warden', 'poll')
        time = float(time) if time else float('-inf')
        return time

    @staticmethod
    def start_profiling():
        print('-' * 30 + ' Started profiling')
        import cProfile

        profile = cProfile.Profile()
        profile.enable()
        return profile

    @staticmethod
    def end_profiling(profile):
        import pstats
        import io

        profile.disable()
        s = io.StringIO()
        sortby = pstats.SortKey.CUMULATIVE
        ps = pstats.Stats(profile, stream=s).sort_stats(sortby)
        ps.print_stats()
        print(s.getvalue())
        print('-' * 30 + ' Done profiling')

    def store_blame_report(self, ip, network_evaluation):
        """
        :param network_evaluation: a dict with {'score': ..,'confidence': .., 'ts': ..} taken from a blame report
        """
        self.rcache.hset('p2p-received-blame-reports', ip, network_evaluation)

    def store_zeek_path(self, path):
        """used to store the path of zeek log files slips is currently using"""
        self.r.set('zeek_path', path)

    def get_zeek_path(self) -> str:
        """return the path of zeek log files slips is currently using"""
        return self.r.get('zeek_path')

    def store_std_file(self, **kwargs):
        """
        available args are
            std_files = {
                    'stderr': ,
                    'stdout': ,
                    'stdin': ,
                    'pidfile': ,
                    'logsfile': ,
                }
        """
        for file_type, path in kwargs.items():
            self.r.set(file_type, path)

    def get_stdfile(self, file_type):
        return self.r.get(file_type)
