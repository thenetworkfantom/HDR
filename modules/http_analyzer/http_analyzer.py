from slips_files.common.imports import *
import json
import urllib
import requests


class HTTPAnalyzer(Module, multiprocessing.Process):
    name = 'HTTP Analyzer'
    description = 'Analyze HTTP flows'
    authors = ['Alya Gomaa']

    def init(self):
        self.c1 = self.db.subscribe('new_http')
        self.channels = {
            'new_http': self.c1
        }
        self.connections_counter = {}
        self.empty_connections_threshold = 4


        self.hosts = ['bing.com', 'google.com', 'yandex.com', 'yahoo.com', 'duckduckgo.com', 'gmail.com']
        self.read_configuration()
        self.executable_mime_types = [
            'application/x-msdownload',
            'application/x-ms-dos-executable',
            'application/x-ms-exe',
            'application/x-exe',
            'application/x-winexe',
            'application/x-winhlp',
            'application/x-winhelp',
            'application/octet-stream',
            'application/x-dosexec'
        ]


    def read_configuration(self):
        conf = ConfigParser()
        self.pastebin_downloads_threshold = conf.get_pastebin_download_threshold()

    def detect_executable_mime_types(self, resp_mime_types: list) -> bool:
        """
        detects the type of file in the http response,
        returns true if it's an executable
        """
        if not resp_mime_types:
            return False

        for mime_type in resp_mime_types:
            if mime_type in self.executable_mime_types:
                return True
        return False

    def check_suspicious_user_agents(
        self, uid, host, uri, timestamp, user_agent, profileid, twid
    ):
        """Check unusual user agents and set evidence"""

        suspicious_user_agents = (
            'httpsend',
            'chm_msdn',
            'pb',
            'jndi',
            'tesseract',
        )
        for suspicious_ua in suspicious_user_agents:
            if suspicious_ua.lower() in user_agent.lower():
                attacker_direction = 'srcip'
                source_target_tag = 'SuspiciousUserAgent'
                attacker = profileid.split('_')[1]
                evidence_type = 'SuspiciousUserAgent'
                threat_level = 'high'
                category = 'Anomaly.Behaviour'
                confidence = 1
                victim = f'{host}{uri}'
                description = f'suspicious user-agent: {user_agent} while connecting to {victim}'
                self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence,
                                         description, timestamp, category, source_target_tag=source_target_tag,
                                         profileid=profileid, twid=twid, uid=uid, victim=victim)
                return True
        return False

    def check_multiple_empty_connections(
        self, uid, contacted_host, timestamp, request_body_len, profileid, twid
    ):
        """
        Detects more than 4 empty connections to google, bing, yandex and yahoo on port 80
        """




        for host in self.hosts:
            if contacted_host in [host, f'www.{host}'] and request_body_len == 0:
                try:

                    uids, connections = self.connections_counter[host]
                    connections +=1
                    uids.append(uid)
                    self.connections_counter[host] = (uids, connections)
                except KeyError:

                    self.connections_counter.update({host: ([uid], 1)})
                break
        else:



            return False

        uids, connections = self.connections_counter[host]
        if connections == self.empty_connections_threshold:
            evidence_type = 'EmptyConnections'
            attacker_direction = 'srcip'
            attacker = profileid.split('_')[0]
            threat_level = 'medium'
            category = 'Anomaly.Connection'
            confidence = 1
            description = f'multiple empty HTTP connections to {host}'
            self.db.setEvidence(evidence_type,
                                attacker_direction,
                                attacker,
                                threat_level,
                                confidence,
                                description,
                                timestamp,
                                category,
                                profileid=profileid,
                                twid=twid,
                                uid=uids,
                                victim=host)

            self.connections_counter[host] = ([], 0)
            return True
        return False

    def set_evidence_incompatible_user_agent(
        self, host, uri, vendor, user_agent, timestamp, profileid, twid, uid
    ):
        attacker_direction = 'srcip'
        source_target_tag = 'IncompatibleUserAgent'
        attacker = profileid.split('_')[1]
        evidence_type = 'IncompatibleUserAgent'
        threat_level = 'high'
        category = 'Anomaly.Behaviour'
        confidence = 1
        os_type = user_agent.get('os_type', '').lower()
        os_name = user_agent.get('os_name', '').lower()
        browser = user_agent.get('browser', '').lower()
        user_agent = user_agent.get('user_agent', '')
        victim = f'{host}{uri}'
        description = (
            f'using incompatible user-agent ({user_agent}) that belongs to OS: {os_name} '
            f'type: {os_type} browser: {browser}. '
            f'while connecting to {victim}. '
            f'IP has MAC vendor: {vendor.capitalize()}'
        )
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, profileid=profileid,
                                 twid=twid, uid=uid, victim=victim)

    def report_executable_mime_type(self, mime_type, attacker, profileid, twid, uid, timestamp):
        confidence = 1
        threat_level = 'low'
        source_target_tag = 'ExecutableMIMEType'
        category = 'Anomaly.File'
        evidence_type = 'ExecutableMIMEType'
        attacker_direction = 'dstip'
        srcip = profileid.split('_')[1]
        ip_identification = self.db.get_ip_identification(attacker)
        description = f'download of an executable with mime type: {mime_type} ' \
                      f'by {srcip} from {attacker} {ip_identification}.'

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, profileid=profileid,
                                 twid=twid, uid=uid)


    def check_incompatible_user_agent(
        self, host, uri, timestamp, profileid, twid, uid
    ):
        """
        Compare the user agent of this profile to the MAC vendor and check incompatibility
        """

        vendor = self.db.get_mac_vendor_from_profile(profileid)
        if not vendor:
            return False
        vendor = vendor.lower()

        user_agent: dict = self.db.get_user_agent_from_profile(profileid)
        if not user_agent or type(user_agent) != dict:
            return False

        os_type = user_agent.get('os_type', '').lower()
        os_name = user_agent.get('os_name', '').lower()
        browser = user_agent.get('browser', '').lower()

        if 'safari' in browser and 'apple' not in vendor:
            self.set_evidence_incompatible_user_agent(
                host, uri, vendor, user_agent, timestamp, profileid, twid, uid
            )
            return True



        os_keywords = [
            ('macos', 'ios', 'apple', 'os x', 'mac', 'macintosh', 'darwin'),
            ('microsoft', 'windows', 'nt'),
            ('android', 'google'),
        ]


        found_vendor_tuple = False
        for tuple_ in os_keywords:
            for keyword in tuple_:
                if keyword in vendor:




                    os_keywords.pop(os_keywords.index(tuple_))
                    found_vendor_tuple = True
                    break
            if found_vendor_tuple:
                break

        if not found_vendor_tuple:


            return False


        for tuple_ in os_keywords:
            for keyword in tuple_:
                if keyword in f'{os_name} {os_type}':



                    self.set_evidence_incompatible_user_agent(
                        host,
                        uri,
                        vendor,
                        user_agent,
                        timestamp,
                        profileid,
                        twid,
                        uid,
                    )

                    return True

    def get_ua_info_online(self, user_agent):
        """
        Get OS and browser info about a use agent from an online database http://useragentstring.com
        """
        url = 'http://useragentstring.com/'
        params = {
            'uas': user_agent,
            'getJSON':'all'
        }
        params = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        try:

            response = requests.get(url, params=params, timeout=5)
            if response.status_code != 200 or not response.text:
                raise requests.exceptions.ConnectionError
        except requests.exceptions.ConnectionError:
            return False





        try:

            json_response = json.loads(response.text)
        except json.decoder.JSONDecodeError:

            return False
        return json_response

    def get_user_agent_info(self, user_agent: str, profileid: str):
        """
        Get OS and browser info about a user agent online
        """

        if not user_agent:
            return False


        self.db.add_all_user_agent_to_profile(profileid, user_agent)


        if self.db.get_user_agent_from_profile(profileid) is not None:

            return False

        UA_info = {
            'user_agent': user_agent,
            'os_type' : '',
            'os_name': ''
        }

        if ua_info := self.get_ua_info_online(user_agent):


            os_type = (
                ua_info.get('os_type', '')
                .replace('unknown', '')
                .replace('  ', '')
            )
            os_name = (
                ua_info.get('os_name', '')
                .replace('unknown', '')
                .replace('  ', '')
            )
            browser = (
                ua_info.get('agent_name', '')
                .replace('unknown', '')
                .replace('  ', '')
            )

            UA_info.update(
                {
                    'os_name': os_name,
                    'os_type': os_type,
                    'browser': browser,
                }
            )

        self.db.add_user_agent_to_profile(profileid, json.dumps(UA_info))
        return UA_info

    def extract_info_from_UA(self, user_agent, profileid):
        """
        Zeek sometimes collects info about a specific UA, in this case the UA starts with
        'server-bag'
        """
        if self.db.get_user_agent_from_profile(profileid) is not None:

            return True


        user_agent = (
            user_agent.replace('server-bag', '')
            .replace(']', '')
            .replace('[', '')
        )
        UA_info = {'user_agent': user_agent}
        os_name = user_agent.split(',')[0]
        os_type = os_name + user_agent.split(',')[1]
        UA_info.update(
            {
                'os_name': os_name,
                'os_type': os_type,

                'browser': '',
            }
        )
        UA_info = json.dumps(UA_info)
        self.db.add_user_agent_to_profile(profileid, UA_info)
        return UA_info

    def check_multiple_UAs(
        self,
        cached_ua: dict,
        user_agent: dict,
        timestamp,
        profileid,
        twid,
        uid,
    ):
        """
        Detect if the user is using an Apple UA, then android, then linux etc.
        Doesn't check multiple ssh clients
        :param user_agent: UA of the current flow
        :param cached_ua: UA of this profile from the db
        """
        if not cached_ua or not user_agent:
            return False
        os_type = cached_ua['os_type']
        os_name = cached_ua['os_name']


        for keyword in (os_type, os_name):

            if keyword in user_agent:



                return False

        attacker_direction = 'srcip'
        source_target_tag = 'MultipleUserAgent'
        attacker = profileid.split('_')[1]
        evidence_type = 'MultipleUserAgent'
        threat_level = 'info'
        category = 'Anomaly.Behaviour'
        confidence = 1
        ua = cached_ua.get('user_agent', '')
        description = (
            f'using multiple user-agents: "{ua}" then "{user_agent}"'
        )
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, profileid=profileid,
                                 twid=twid, uid=uid)
        return True


    def set_evidence_http_traffic(self, daddr, profileid, twid, uid, timestamp):
        """
        Detect when a new HTTP flow is found stating that the traffic is unencrypted
        """
        confidence = 1
        threat_level = 'low'
        source_target_tag = 'SendingUnencryptedData'
        category = 'Anomaly.Traffic'
        evidence_type = 'HTTPtraffic'
        attacker_direction = 'dstip'
        attacker = daddr
        saddr = profileid.split('_')[-1]
        description = (f'Unencrypted HTTP traffic from {saddr} to {daddr}.')

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, profileid=profileid,
                                 twid=twid, uid=uid)
        return True


    def check_pastebin_downloads(
            self,
            daddr,
            response_body_len,
            method,
            profileid,
            twid,
            timestamp,
            uid
    ):
        try:
            response_body_len = int(response_body_len)
        except ValueError:
            return False

        ip_identification = self.db.get_ip_identification(daddr)
        if ('pastebin' in ip_identification
            and response_body_len > self.pastebin_downloads_threshold
            and method == 'GET'):
            attacker_direction = 'dstip'
            source_target_tag = 'Malware'
            attacker = daddr
            evidence_type = 'PastebinDownload'
            threat_level = 'info'
            category = 'Anomaly.Behaviour'
            confidence = 1
            response_body_len = utils.convert_to_mb(response_body_len)
            description = (
               f'A downloaded file from pastebin.com. size: {response_body_len} MBs'
            )
            self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence,
                                     description, timestamp, category, source_target_tag=source_target_tag,
                                     profileid=profileid, twid=twid, uid=uid)
            return True


    def pre_main(self):
        utils.drop_root_privs()

    def main(self):
        if msg:= self.get_msg('new_http'):
            message = json.loads(msg['data'])
            profileid = message['profileid']
            twid = message['twid']
            flow = json.loads(message['flow'])
            uid = flow['uid']
            host = flow['host']
            uri = flow['uri']
            daddr = flow['daddr']
            timestamp = flow.get('stime', '')
            user_agent = flow.get('user_agent', False)
            request_body_len = flow.get('request_body_len')
            response_body_len = flow.get('response_body_len')
            method = flow.get('method')
            resp_mime_types = flow.get('resp_mime_types')

            self.check_suspicious_user_agents(
                uid, host, uri, timestamp, user_agent, profileid, twid
            )
            self.check_multiple_empty_connections(
                uid, host, timestamp, request_body_len, profileid, twid
            )


            cached_ua = self.db.get_user_agent_from_profile(
                profileid
            )
            if cached_ua:
                self.check_multiple_UAs(
                    cached_ua,
                    user_agent,
                    timestamp,
                    profileid,
                    twid,
                    uid,
                )

            if (
                not cached_ua
                or (type(cached_ua) == dict
                    and cached_ua.get('user_agent', '') != user_agent
                    and 'server-bag' not in user_agent)
            ):

                self.get_user_agent_info(
                    user_agent,
                    profileid
                )

            if 'server-bag' in user_agent:
                self.extract_info_from_UA(
                    user_agent,
                    profileid
                )

            if self.detect_executable_mime_types(resp_mime_types):
                self.report_executable_mime_type(
                    resp_mime_types,
                    daddr,
                    profileid,
                    twid,
                    uid,
                    timestamp
                )

            self.check_incompatible_user_agent(
                host,
                uri,
                timestamp,
                profileid,
                twid,
                uid
            )

            self.check_pastebin_downloads(
                daddr,
                response_body_len,
                method,
                profileid,
                twid,
                timestamp,
                uid
            )


            self.set_evidence_http_traffic(
                daddr,
                profileid,
                twid,
                uid,
                timestamp
            )
