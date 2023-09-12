import json
import ast

class IoCHandler():
    """
    Helper class for the Redis class in database.py
    Contains all the logic related to setting and retrieving evidence and alerts in the db
    """
    name = 'DB'


    def set_loaded_ti_files(self, number_of_loaded_files: int):
        """
        Stores the number of successfully loaded TI files
        """
        self.r.set('loaded TI files', number_of_loaded_files)

    def get_loaded_ti_files(self):
        """
        returns the number of successfully loaded TI files. or 0 if none is loaded
        """
        return self.r.get('loaded TI files') or 0

    def give_threat_intelligence(
            self, profileid, twid, ip_state, starttime, uid, daddr, proto=False, lookup='', extra_info:dict =False
    ):
        data_to_send = {
                'to_lookup': str(lookup),
                'profileid': str(profileid),
                'twid': str(twid),
                'proto': str(proto),
                'ip_state': ip_state,
                'stime': starttime,
                'uid': uid,
                'daddr': daddr
        }
        if extra_info:

            data_to_send.update(extra_info)

        self.publish(
            'give_threat_intelligence', json.dumps(data_to_send)
        )

        return data_to_send

    def delete_ips_from_IoC_ips(self, ips):
        """
        Delete old IPs from IoC
        """
        self.rcache.hdel('IoC_ips', *ips)

    def delete_domains_from_IoC_domains(self, domains):
        """
        Delete old domains from IoC
        """
        self.rcache.hdel('IoC_domains', *domains)

    def add_ips_to_IoC(self, ips_and_description: dict) -> None:
        """
        Store a group of IPs in the db as they were obtained from an IoC source
        :param ips_and_description: is {ip: json.dumps{'source':..,
                                                        'tags':..,
                                                        'threat_level':... ,
                                                        'description':...}}

        """
        if ips_and_description:
            self.rcache.hmset('IoC_ips', ips_and_description)

    def add_domains_to_IoC(self, domains_and_description: dict) -> None:
        """
        Store a group of domains in the db as they were obtained from
        an IoC source
        :param domains_and_description: is {domain: json.dumps{'source':..,'tags':..,
                                                            'threat_level':... ,'description'}}
        """
        if domains_and_description:
            self.rcache.hmset('IoC_domains', domains_and_description)

    def add_ip_range_to_IoC(self, malicious_ip_ranges: dict) -> None:
        """
        Store a group of IP ranges in the db as they were obtained from an IoC source
        :param malicious_ip_ranges: is {range: json.dumps{'source':..,'tags':..,
                                                            'threat_level':... ,'description'}}
        """
        if malicious_ip_ranges:
            self.rcache.hmset('IoC_ip_ranges', malicious_ip_ranges)

    def add_asn_to_IoC(self, blacklisted_ASNs: dict):
        """
        Store a group of ASN in the db as they were obtained from an IoC source
        :param blacklisted_ASNs: is {asn: json.dumps{'source':..,'tags':..,
                                                     'threat_level':... ,'description'}}
        """
        if blacklisted_ASNs:
            self.rcache.hmset('IoC_ASNs', blacklisted_ASNs)

    def is_blacklisted_ASN(self, ASN) -> bool:
        return self.rcache.hget('IoC_ASNs', ASN)


    def add_ja3_to_IoC(self, ja3: dict) -> None:
        """
        Store the malicious ja3 iocs in the db
        :param ja3:  {ja3: {'source':..,'tags':..,
                            'threat_level':... ,'description'}}

        """
        self.rcache.hmset('IoC_JA3', ja3)

    def add_jarm_to_IoC(self, jarm: dict) -> None:
        """
        Store the malicious jarm iocs in the db
        :param jarm:  {jarm: {'source':..,'tags':..,
                            'threat_level':... ,'description'}}
        """
        self.rcache.hmset('IoC_JARM', jarm)

    def add_ssl_sha1_to_IoC(self, malicious_ssl_certs):
        """
        Store a group of ssl fingerprints in the db
        :param malicious_ssl_certs:  {sha1: {'source':..,'tags':..,
                                    'threat_level':... ,'description'}}

        """
        self.rcache.hmset('IoC_SSL', malicious_ssl_certs)

    def get_malicious_ip_ranges(self) -> dict:
        """
        Returns all the malicious ip ranges we have from different feeds
        return format is {range: json.dumps{'source':..,'tags':..,
                                            'threat_level':... ,'description'}}
        """
        return self.rcache.hgetall('IoC_ip_ranges')
    def get_IPs_in_IoC(self):
        """
        Get all IPs and their description from IoC_ips
        """
        return self.rcache.hgetall('IoC_ips')

    def get_Domains_in_IoC(self):
        """
        Get all Domains and their description from IoC_domains
        """
        return self.rcache.hgetall('IoC_domains')

    def get_ja3_in_IoC(self):
        """
        Get all ja3 and their description from IoC_JA3
        """
        return self.rcache.hgetall('IoC_JA3')

    def is_malicious_jarm(self, jarm_hash: str):
        """
        search for the given hash in the malicious hashes stored in the db
        """
        return self.rcache.hget('IoC_JARM', jarm_hash)

    def search_IP_in_IoC(self, ip: str) -> str:
        """
        Search in the dB of malicious IPs and return a
        description if we found a match
        """
        ip_description = self.rcache.hget('IoC_ips', ip)
        return False if ip_description is None else ip_description


    def set_malicious_ip(self, ip, profileid, twid):
        """
        Save in DB malicious IP found in the traffic
        with its profileid and twid
        """
        if not profileid:


            return False

        ip_profileid_twid = self.get_malicious_ip(ip)
        try:
            profile_tws = ip_profileid_twid[
                profileid
            ]
            profile_tws = ast.literal_eval(
                profile_tws
            )
            profile_tws.add(twid)
            ip_profileid_twid[profileid] = str(profile_tws)
        except KeyError:
            ip_profileid_twid[profileid] = str(
                {twid}
            )
        data = json.dumps(ip_profileid_twid)

        self.r.hset('MaliciousIPs', ip, data)

    def set_malicious_domain(self, domain, profileid, twid):
        """
        Save in DB a malicious domain found in the traffic
        with its profileid and twid
        """
        if not profileid:


            return False

        domain_profiled_twid = self.get_malicious_domain(domain)
        try:
            profile_tws = domain_profiled_twid[
                profileid
            ]
            profile_tws = ast.literal_eval(
                profile_tws
            )
            profile_tws.add(twid)
            domain_profiled_twid[profileid] = str(profile_tws)
        except KeyError:
            domain_profiled_twid[profileid] = str(
                {twid}
            )
        data = json.dumps(domain_profiled_twid)

        self.r.hset('MaliciousDomains', domain, data)

    def get_malicious_ip(self, ip):
        """
        Return malicious IP and its list of presence in
        the traffic (profileid, twid)
        """
        data = self.r.hget('MaliciousIPs', ip)
        data = json.loads(data) if data else {}
        return data

    def get_malicious_domain(self, domain):
        """
        Return malicious domain and its list of presence in
        the traffic (profileid, twid)
        """
        data = self.r.hget('MaliciousDomains', domain)
        data = json.loads(data) if data else {}
        return data

    def get_ssl_info(self, sha1):
        info = self.rcache.hmget('IoC_SSL', sha1)[0]
        return False if info is None else info
    def is_domain_malicious(self, domain: str) -> tuple:
        """
        Search in the dB of malicious domains and return a
        description if we found a match
        returns a tuple (description, is_subdomain)
        description: description of the subdomain if found
        bool: True if we found a match for exactly the given domain False if we matched a subdomain
        """
        domain_description = self.rcache.hget('IoC_domains', domain)
        if domain_description is None:

            ioc_domains = self.rcache.hgetall('IoC_domains')
            for malicious_domain, description in ioc_domains.items():

                if malicious_domain in domain:
                    return description, True
            return False, False
        else:
            return domain_description, False

    def delete_feed(self, url: str):
        """
        Delete all entries in IoC_domains and IoC_ips that contain the given feed as source
        """

        feed_to_delete = url.split('/')[-1]

        IoC_domains = self.rcache.hgetall('IoC_domains')
        for domain, domain_description in IoC_domains.items():
            domain_description = json.loads(domain_description)
            if feed_to_delete in domain_description['source']:

                self.rcache.hdel('IoC_domains', domain)


        IoC_ips = self.rcache.hgetall('IoC_ips')
        for ip, ip_description in IoC_ips.items():
            ip_description = json.loads(ip_description)
            if feed_to_delete in ip_description['source']:

                self.rcache.hdel('IoC_ips', ip)

    def is_profile_malicious(self, profileid: str) -> str:
        return self.r.hget(profileid, 'labeled_as_malicious') if profileid else False

    def set_TI_file_info(self, file, data):
        """
        Set/update time and/or e-tag for TI file
        :param file: a valid filename not a feed url
        :param data: dict containing info about TI file
        """



        data = json.dumps(data)
        self.rcache.hset('TI_files_info', file, data)

    def set_last_update_time(self, file: str, time: float):
        """
        sets the 'time' of last update of the given file
        :param file: ti file
        """
        if file_info := self.rcache.hget('TI_files_info', file):

            file_info = json.loads(file_info)
            file_info.update({"time": time})
            self.rcache.hset('TI_files_info', file, json.dumps(file_info))
            return


        self.rcache.hset('TI_files_info', file, json.dumps({"time": time}))

    def get_TI_file_info(self, file):
        """
        Get TI file info
        :param file: a valid filename not a feed url
        """
        data = self.rcache.hget('TI_files_info', file)
        data = json.loads(data) if data else {}
        return data

    def delete_file_info(self, file):
        self.rcache.hdel('TI_files_info', file)

    def getURLData(self, url):
        """
        Return information about this URL
        Returns a dictionary or False if there is no IP in the database
        We need to separate these three cases:
        1- IP is in the DB without data. Return empty dict.
        2- IP is in the DB with data. Return dict.
        3- IP is not in the DB. Return False
        """
        data = self.rcache.hget('URLsInfo', url)
        data = json.loads(data) if data else False
        return data

    def setNewURL(self, url: str):
        """
        1- Stores this new URL in the URLs hash
        2- Publishes in the channels that there is a new URL, and that we want
            data from the Threat Intelligence modules
        """
        data = self.getURLData(url)
        if data is False:





            self.rcache.hset('URLsInfo', url, '{}')

    def getDomainData(self, domain):
        """
        Return information about this domain
        Returns a dictionary or False if there is no domain in the database
        We need to separate these three cases:
        1- Domain is in the DB without data. Return empty dict.
        2- Domain is in the DB with data. Return dict.
        3- Domain is not in the DB. Return False
        """
        data = self.rcache.hget('DomainsInfo', domain)
        data = json.loads(data) if data or data == {} else False
        return data

    def setNewDomain(self, domain: str):
        """
        1- Stores this new domain in the Domains hash
        2- Publishes in the channels that there is a new domain, and that we want
            data from the Threat Intelligence modules
        """
        data = self.getDomainData(domain)
        if data is False:





            self.rcache.hset('DomainsInfo', domain, '{}')

    def setInfoForDomains(self, domain: str, info_to_set: dict, mode='leave'):
        """
        Store information for this domain
        :param info_to_set: a dictionary, such as {'geocountry': 'rumania'} that we are
        going to store for this domain
        :param mode: defines how to deal with the new data
        - to 'overwrite' the data with the new data
        - to 'add' the data to the new data
        - to 'leave' the past data untouched
        """


        domain_data = self.getDomainData(domain)
        if not domain_data:

            self.setNewDomain(domain)

            domain_data = self.getDomainData(domain)


        for key in iter(info_to_set):
            if type(domain_data) == str:
                domain_data = json.loads(domain_data)


            data_to_store = info_to_set[key]


            try:
                _ = domain_data[key]
                if type(data_to_store) != list:

                    data_to_store = [data_to_store]

                if mode == 'overwrite':
                    domain_data[key] = data_to_store
                elif mode == 'add':
                    prev_info = domain_data[key]

                    if type(prev_info) == list:

                        prev_info.extend(data_to_store)
                        domain_data[key] = list(set(prev_info))
                    elif type(prev_info) == str:

                        prev_info = [prev_info]

                        domain_data[key] = prev_info.extend(data_to_store)
                    elif prev_info is None:

                        domain_data[key] = data_to_store

                elif mode == 'leave':
                    return

            except KeyError:

                if type(data_to_store) == list:
                    domain_data[key] = list(set(data_to_store))
                else:
                    domain_data[key] = data_to_store

            domain_data = json.dumps(domain_data)
            self.rcache.hset('DomainsInfo', domain, domain_data)

            self.r.publish('dns_info_change', domain)

    def setInfoForURLs(self, url: str, urldata: dict):
        """
        Store information for this URL
        We receive a dictionary, such as {'VirusTotal': {'URL':score}} that we are
        going to store for this IP.
        If it was not there before we store it. If it was there before, we
        overwrite it
        """
        data = self.getURLData(url)
        if data is False:
            self.setNewURL(url)
            data = self.getIPData(url)

        dict_has_keys = bool(data)
        if dict_has_keys:

            for key in iter(data):
                data_to_store = urldata[key]
                try:

                    _ = data[key]
                except KeyError:
                    pass


                data[key] = data_to_store
                newdata_str = json.dumps(data)
                self.rcache.hset('URLsInfo', url, newdata_str)
        else:

            urldata = json.dumps(urldata)
            self.rcache.hset('URLsInfo', url, urldata)
