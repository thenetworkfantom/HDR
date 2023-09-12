from slips_files.common.slips_utils import utils
from slips_files.common.config_parser import ConfigParser
from slips_files.core.database.sqlite_db.database import SQLiteDB
from dataclasses import asdict
import redis
import time
import json
from typing import Tuple
import traceback
import ipaddress
import sys
import validators

class ProfileHandler():
    """
    Helper class for the Redis class in database.py
    Contains all the logic related to flows, profiles and timewindows
    """
    name = 'DB'

    def get_data_from_profile_tw(self, hash_key: str, key_name: str):
        try:
            """
            key_name = [Src,Dst] + [Port,IP] + [Client,Server] + [TCP,UDP, ICMP, ICMP6] + [Established, NotEstablihed]
            Example: key_name = 'SrcPortClientTCPEstablished'
            """
            data = self.r.hget(hash_key, key_name)
            value = {}
            if data:
                portdata = json.loads(data)
                value = portdata
            return value
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.outputqueue.put(
                f'01|database|[DB] Error in getDataFromProfileTW in database.py line {exception_line}'
            )
            self.outputqueue.put(f'01|database|[DB] {traceback.print_exc()}')

    def getOutTuplesfromProfileTW(self, profileid, twid):
        """Get the out tuples"""
        return self.r.hget(profileid + self.separator + twid, 'OutTuples')

    def getInTuplesfromProfileTW(self, profileid, twid):
        """Get the in tuples"""
        return self.r.hget(profileid + self.separator + twid, 'InTuples')
    def get_dhcp_flows(self, profileid, twid) -> list:
        """
        returns a dict of dhcp flows that happened in this profileid and twid
        """
        if flows := self.r.hget('DHCP_flows', f'{profileid}_{twid}'):
            return json.loads(flows)

    def set_dhcp_flow(self, profileid, twid, requested_addr, uid):
        """
        Stores all dhcp flows sorted by profileid_twid
        """
        flow = {requested_addr: uid}
        if cached_flows := self.get_dhcp_flows(profileid, twid):

            cached_flows.update(flow)
            self.r.hset('DHCP_flows', f'{profileid}_{twid}', json.dumps(cached_flows))
        else:
            self.r.hset('DHCP_flows', f'{profileid}_{twid}', json.dumps(flow))


    def get_timewindow(self, flowtime, profileid):
        """
        This function should get the id of the TW in the database where the flow belong.
        If the TW is not there, we create as many tw as necessary in the future or past until we get the correct TW for this flow.
        - We use this function to avoid retrieving all the data from the DB for the complete profile. We use a separate table for the TW per profile.
        -- Returns the time window id
        THIS IS NOT WORKING:
        - The empty profiles in the middle are not being created!!!
        - The Dtp ips are stored in the first time win
        """
        try:

            try:
                if not profileid:


                    return False
                [(lasttwid, lasttw_start_time)] = self.get_last_twid_of_profile(profileid)
                lasttw_start_time = float(lasttw_start_time)
                lasttw_end_time = lasttw_start_time + self.width
                flowtime = float(flowtime)
                self.print(
                    f'The last TW id for profile {profileid} was {lasttwid}. Start:{lasttw_start_time}. End: {lasttw_end_time}',
                    3,
                    0,
                )

                if (
                    lasttw_end_time > flowtime
                    and lasttw_start_time <= flowtime
                ):
                    self.print(
                        f'The flow ({flowtime}) is on the last time window ({lasttw_end_time})',
                        3,
                        0,
                    )
                    twid = lasttwid
                elif lasttw_end_time <= flowtime:

                    self.print(
                        f'The flow ({flowtime}) is NOT on the last time window ({lasttw_end_time}). Its newer',
                        3,
                        0,
                    )
                    amount_of_new_tw = int(
                        (flowtime - lasttw_end_time) / self.width
                    )
                    self.print(
                        f'We have to create {amount_of_new_tw} empty TWs in the middle.',
                        3,
                        0,
                    )
                    temp_end = lasttw_end_time
                    for _ in range(amount_of_new_tw + 1):
                        new_start = temp_end
                        twid = self.addNewTW(profileid, new_start)
                        self.print(f'Creating the TW id {twid}. Start: {new_start}.', 3, 0)
                        temp_end = new_start + self.width

                else:

                    self.print(
                        f'The flow ({flowtime}) is NOT on the last time window ({lasttw_end_time}). Its older',
                        3,
                        0,
                    )
                    if data := self.getTWofTime(profileid, flowtime):

                        (twid, tw_start_time) = data
                        return twid
                    else:



                        amount_of_new_tw = int(
                            (lasttw_end_time - flowtime) / self.width
                        )

                        amount_of_current_tw = (
                            self.get_number_of_tws_in_profile(profileid)
                        )

                        diff = amount_of_new_tw - amount_of_current_tw
                        self.print(f'We need to create {diff + 1} TW before the first', 3, 0)

                        [
                            (firsttwid, firsttw_start_time)
                        ] = self.getFirstTWforProfile(profileid)
                        firsttw_start_time = float(firsttw_start_time)

                        temp_start = firsttw_start_time - self.width
                        for _ in range(diff + 1):
                            new_start = temp_start


                            twid = self.addNewOlderTW(
                                profileid, new_start
                            )
                            self.print(f'Creating the new older TW id {twid}. Start: {new_start}.', 3, 0)
                            temp_start = new_start - self.width
            except ValueError:



                if self.width == 9999999999:

                    startoftw = float(flowtime - (31536000 * 100))
                else:
                    startoftw = flowtime


                twid = self.addNewTW(profileid, startoftw)

            return twid
        except Exception as e:
            self.print('Error in get_timewindow().', 0, 1)
            self.print(f'{e}', 0, 1)

    def add_out_http(
        self,
        profileid,
        twid,
        flow,
    ):
        """
        Store in the DB a http request
        All the type of flows that are not netflows are stored in a separate hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which other type of info is related to that uid
        """
        http_flow_dict = {
            'uid': flow.uid,
            'type': flow.type_,
            'method': flow.method,
            'host': flow.host,
            'uri': flow.uri,
            'version': flow.version,
            'user_agent': flow.user_agent,
            'request_body_len': flow.request_body_len,
            'response_body_len': flow.response_body_len,
            'status_code': flow.status_code,
            'status_msg': flow.status_msg,
            'resp_mime_types': flow.resp_mime_types,
            'resp_fuids': flow.resp_fuids,
            'stime': flow.starttime,
            'daddr': flow.daddr,
        }

        http_flow_dict = json.dumps(http_flow_dict)
        http_flow = {
            'profileid': profileid,
            'twid': twid,
            'flow': http_flow_dict,
            'stime': flow.starttime,
        }
        to_send = json.dumps(http_flow)
        self.publish('new_http', to_send)
        self.publish('new_url', to_send)

        self.print(f'Adding HTTP flow to DB: {http_flow_dict}', 3, 0)

        http_flow.pop('flow', None)
        http_flow['uid'] = flow.uid



        if len(flow.host) > 2:
            self.give_threat_intelligence(profileid,
                                          twid,
                                          'dst',
                                          flow.starttime,
                                          flow.uid,
                                          flow.daddr,
                                          lookup=flow.host)
            self.give_threat_intelligence(profileid,
                                          twid,
                                          'dst',
                                          flow.starttime,
                                          flow.uid,
                                          flow.daddr,
                                          lookup=f'http://{flow.host}{flow.uri}')
        else:

            self.give_threat_intelligence(profileid,
                                          twid,
                                          'dstip',
                                          flow.starttime,
                                          flow.uid,
                                          flow.daddr,
                                          lookup=f'http://{flow.daddr}{flow.uri}')



    def add_out_dns(
        self,
        profileid,
        twid,
        flow
    ):
        """
        Store in the DB a DNS request
        All the type of flows that are not netflows are stored in a separate hash ordered by flow.uid.
        The idea is that from the flow.uid of a netflow, you can access which other type of info is related to that flow.uid
        """
        dns_flow = {
            'flow.uid': flow.uid,
            'type': flow.type_,
            'query': flow.query,
            'qclass_name': flow.qclass_name,
            'flow.qtype_name': flow.qtype_name,
            'rcode_name': flow.rcode_name,
            'answers': flow.answers,
            'ttls': flow.TTLs,
            'stime': flow.starttime,
        }


        dns_flow = json.dumps(dns_flow)


        to_send = {
            'profileid': profileid,
            'twid': twid,
            'flow': dns_flow,
            'stime': flow.starttime,
            'uid': flow.uid,
            'rcode_name': flow.rcode_name,
            'daddr': flow.daddr,
            'answers': flow.answers
        }

        to_send = json.dumps(to_send)

        self.publish('new_dns', to_send)

        self.give_threat_intelligence(
            profileid,
            twid,
            'dstip',
            flow.starttime,
            flow.uid,
            flow.daddr,
            lookup=flow.query
        )



        if flow.answers and flow.answers !=  ['-'] :
            srcip = profileid.split('_')[1]
            self.set_dns_resolution(
                flow.query, flow.answers, flow.starttime, flow.uid, flow.qtype_name, srcip, twid
            )

            for answer in flow.answers:
                if 'TXT' in answer:
                    continue

                extra_info = {
                    'is_dns_response': True,
                    'dns_query': flow.query,
                    'domain': answer,
                }
                self.give_threat_intelligence(
                    profileid,
                    twid,
                    'dstip',
                    flow.starttime,
                    flow.uid,
                    flow.daddr,
                    lookup=answer,
                    extra_info=extra_info
                )


    def add_port(
            self, profileid: str, twid: str, flow: dict, role: str, port_type: str
    ):
        """
        Store info learned from ports for this flow
        The flow can go out of the IP (we are acting as Client) or into the IP (we are acting as Server)
        role: 'Client' or 'Server'. Client also defines that the flow is going out, Server that is going in
        port_type: 'Dst' or 'Src'.
        Depending if this port was a destination port or a source port
        """

        dport = flow.dport
        sport = flow.sport
        totbytes = int(flow.bytes)
        pkts = int(flow.pkts)
        state = flow.state
        proto = flow.proto.upper()
        starttime = str(flow.starttime)
        uid = flow.uid
        ip = str(flow.daddr)
        spkts = flow.spkts
        state_hist = flow.state_hist if hasattr(flow, 'state_hist') else ''





        if '^' in state_hist:








            return False



        port = str(sport) if port_type == 'Src' else str(dport)



        ip_key = 'srcips' if role == 'Server' else 'dstips'


        summaryState = self.getFinalStateFromFlags(state, pkts)

        old_profileid_twid_data = self.getDataFromProfileTW(
            profileid,
            twid,
            port_type,
            summaryState,
            proto,
            role,
            'Ports'
        )

        try:

            port_data = old_profileid_twid_data[port]
            port_data['totalflows'] += 1
            port_data['totalpkt'] += pkts
            port_data['totalbytes'] += totbytes


            if ip in port_data[ip_key]:
                port_data[ip_key][ip]['pkts'] += pkts
                port_data[ip_key][ip]['spkts'] += spkts
                port_data[ip_key][ip]['uid'].append(uid)
            else:
                port_data[ip_key][ip] = {
                    'pkts': pkts,
                    'spkts': spkts,
                    'stime': starttime,
                    'uid': [uid]
                }

        except KeyError:

            port_data = {
                'totalflows': 1,
                'totalpkt': pkts,
                'totalbytes': totbytes,
                ip_key: {
                    ip: {
                        'pkts': pkts,
                        'spkts': spkts,
                        'stime': starttime,
                        'uid': [uid]
                    }
                }
            }
        old_profileid_twid_data[port] = port_data
        data = json.dumps(old_profileid_twid_data)
        hash_key = f'{profileid}{self.separator}{twid}'
        key_name = f'{port_type}Ports{role}{proto}{summaryState}'
        self.r.hset(hash_key, key_name, str(data))
        self.markProfileTWAsModified(profileid, twid, starttime)
    def getFinalStateFromFlags(self, state, pkts):
        """
        Analyze the flags given and return a summary of the state. Should work with Argus and Bro flags
        We receive the pakets to distinguish some Reset connections
        """
        try:

            pre = state.split('_')[0]
            try:

                """
                There are different states in which a flow can be.
                Suricata distinguishes three flow-states for TCP and two for UDP. For TCP,
                these are: New, Established and Closed,for UDP only new and established.
                For each of these states Suricata can employ different timeouts.
                """
                if 'new' in state or 'established' in state:
                    return 'Established'
                elif 'closed' in state:
                    return 'Not Established'


                if (
                    'S0' in state
                    or 'REJ' in state
                    or 'RSTOS0' in state
                    or 'RSTRH' in state
                    or 'SH' in state
                    or 'SHR' in state
                ):
                    return 'Not Established'
                elif (
                    'S1' in state
                    or 'SF' in state
                    or 'S2' in state
                    or 'S3' in state
                    or 'RSTO' in state
                    or 'RSTP' in state
                    or 'OTH' in state
                ):
                    return 'Established'

                suf = state.split('_')[1]
                if 'S' in pre and 'A' in pre and 'S' in suf and 'A' in suf:
                    """
                    Examples:
                    SA_SA
                    SR_SA
                    FSRA_SA
                    SPA_SPA
                    SRA_SPA
                    FSA_FSA
                    FSA_FSPA
                    SAEC_SPA
                    SRPA_SPA
                    FSPA_SPA
                    FSRPA_SPA
                    FSPA_FSPA
                    FSRA_FSPA
                    SRAEC_SPA
                    FSPA_FSRPA
                    FSAEC_FSPA
                    FSRPA_FSPA
                    SRPAEC_SPA
                    FSPAEC_FSPA
                    SRPAEC_FSRPA
                    """
                    return 'Established'
                elif 'PA' in pre and 'PA' in suf:

                    """
                    Examples:
                    PA_PA
                    FPA_FPA
                    """
                    return 'Established'
                elif 'ECO' in pre:
                    return 'ICMP Echo'
                elif 'ECR' in pre:
                    return 'ICMP Reply'
                elif 'URH' in pre:
                    return 'ICMP Host Unreachable'
                elif 'URP' in pre:
                    return 'ICMP Port Unreachable'
                else:
                    """
                    Examples:
                    S_RA
                    S_R
                    A_R
                    S_SA
                    SR_SA
                    FA_FA
                    SR_RA
                    SEC_RA
                    """
                    return 'Not Established'
            except IndexError:

                if 'ECO' in pre:

                    return 'Established'
                elif 'UNK' in pre:

                    return 'Established'
                elif 'CON' in pre:

                    return 'Established'
                elif 'INT' in pre:


                    return 'Not Established'
                elif 'EST' in pre:

                    return 'Established'
                elif 'RST' in pre:



                    return 'Not Established' if int(pkts) <= 3 else 'Established'
                elif 'FIN' in pre:



                    return 'Not Established' if int(pkts) <= 3 else 'Established'
                else:
                    """
                    Examples:
                    S_
                    FA_
                    PA_
                    FSA_
                    SEC_
                    SRPA_
                    """
                    return 'Not Established'
            return None
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.outputqueue.put(
                f'01|database|[DB] Error in getFinalStateFromFlags() in database.py line {exception_line}'
            )
            self.outputqueue.put(f'01|database|[DB] Inst: {traceback.print_exc()}')

    def getDataFromProfileTW(
        self,
        profileid: str,
        twid: str,
        direction: str,
        state: str,
        protocol: str,
        role: str,
        type_data: str,
    ) -> dict:
        """
        Get the info about a certain role (Client or Server),
        for a particular protocol (TCP, UDP, ICMP, etc.) for a
        particular State (Established, etc.)
        direction: 'Dst' or 'Src'. This is used to know if you
        want the data of the src ip or ports, or the data from
        the dst ips or ports
        state: can be 'Established' or 'NotEstablished'
        protocol: can be 'TCP', 'UDP', 'ICMP' or 'IPV6ICMP'
        role: can be 'Client' or 'Server'
        type_data: can be 'Ports' or 'IPs'
        """
        if not profileid:


            return False
        try:
            key = direction + type_data + role + protocol + state

            data = self.r.hget(f'{profileid}{self.separator}{twid}', key)
            value = {}
            if data:
                portdata = json.loads(data)
                value = portdata
            else:
                self.print(
                    f'There is no data for Key: {key}. Profile {profileid} TW {twid}',
                    3,
                    0,
                )
            return value
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.outputqueue.put(
                f'01|database|[DB] Error in getDataFromProfileTW database.py line {exception_line}'
            )
            self.outputqueue.put(f'01|database|[DB] Inst: {traceback.print_exc()}')

    def add_ips(self, profileid, twid, flow, role):
        """
        Function to add information about an IP address
        The flow can go out of the IP (we are acting as Client) or into the IP
        (we are acting as Server)
        ip_as_obj: IP to add. It can be a dstIP or srcIP depending on the role
        role: 'Client' or 'Server'
        This function does two things:
            1- Add the ip to this tw in this profile, counting how many times
            it was contacted, and storing it in the key 'DstIPs' or 'SrcIPs'
            in the hash of the profile
            2- Use the ip as a key to count how many times that IP was
            contacted on each port. We store it like this because its the
               pefect structure to detect vertical port scans later on
            3- Check if this IP has any detection in the threat intelligence
            module. The information is added by the module directly in the DB.
        """

        uid = flow.uid
        starttime = str(flow.starttime)
        ip = flow.daddr if role=='Client' else flow.saddr

        """
        Depending if the traffic is going out or not, we are Client or Server
        Client role means:
            The profile corresponds to the src ip that received this flow
            The dstip is here the one receiving data from your profile
            So check the dst ip
        Server role means:
            The profile corresponds to the dst ip that received this flow
            The srcip is here the one sending data to your profile
            So check the src ip
        """
        direction = 'Dst' if role == 'Client' else 'Src'





        self.set_new_ip(ip)




        if flow.state != 'OTH':
            self.ask_for_ip_info(flow.saddr,
                                 profileid,
                                 twid,
                                 flow.proto.upper(),
                                 flow.starttime,
                                 flow.uid,
                                 'srcip',
                                 daddr=flow.daddr)
            self.ask_for_ip_info(flow.daddr,
                                 profileid,
                                 twid,
                                 flow.proto.upper(),
                                 flow.starttime,
                                 flow.uid,
                                 'dstip')


        self.update_times_contacted(ip, direction, profileid, twid)


        summaryState = self.getFinalStateFromFlags(flow.state, flow.pkts)


        old_profileid_twid_data = self.getDataFromProfileTW(
            profileid,
            twid,
            direction,
            summaryState,
            flow.proto,
            role,
            'IPs',
        )

        profileid_twid_data = self.update_ip_info(
            old_profileid_twid_data,
            flow.pkts,
            flow.dport,
            flow.spkts,
            flow.bytes,
            ip,
            starttime,
            uid
        )


        key_name = (
            f'{direction}IPs{role}{flow.proto.upper()}{summaryState}'
        )

        self.r.hset(
            f'{profileid}{self.separator}{twid}',
            key_name,
            json.dumps(profileid_twid_data)
        )
        return True

    def get_all_contacted_ips_in_profileid_twid(self, profileid, twid) -> dict:
        """
        Get all the contacted IPs in a given profile and TW
        """
        if not profileid:


            return {}
        all_flows: dict = self.db.get_all_flows_in_profileid_twid(profileid, twid)
        if not all_flows:
            return {}
        contacted_ips = {}
        for uid, flow in all_flows.items():

            daddr = flow['daddr']
            contacted_ips[daddr] = uid
        return contacted_ips


    def markProfileTWAsBlocked(self, profileid, twid):
        """Add this profile and tw to the list of blocked"""
        tws = self.getBlockedProfTW(profileid)
        tws.append(twid)
        self.r.hset('BlockedProfTW', profileid, json.dumps(tws))


    def getBlockedProfTW(self, profileid):
        """Return all the list of blocked tws"""
        if tws := self.r.hget('BlockedProfTW', profileid):
            return json.loads(tws)
        return []


    def checkBlockedProfTW(self, profileid, twid):
        """
        Check if profile and timewindow is blocked
        """
        profile_tws = self.getBlockedProfTW(profileid)
        return twid in profile_tws


    def wasProfileTWModified(self, profileid, twid):
        """Retrieve from the db if this TW of this profile was modified"""
        data = self.r.zrank('ModifiedTW', profileid + self.separator + twid)
        return bool(data)
    def add_flow(
        self,
        flow,
        profileid='',
        twid='',
        label='',
    ):
        """
        Function to add a flow by interpreting the data. The flow is added to the correct TW for this profile.
        The profileid is the main profile that this flow is related too.
        : param new_profile_added : is set to True for everytime we see a new srcaddr
        """
        summaryState = self.getFinalStateFromFlags(flow.state, flow.pkts)
        flow_dict = {
            'ts': flow.starttime,
            'dur': flow.dur,
            'saddr': flow.saddr,
            'sport': flow.sport,
            'daddr': flow.daddr,
            'dport': flow.dport,
            'proto': flow.proto,
            'origstate': flow.state,
            'state': summaryState,
            'pkts': flow.pkts,
            'allbytes': flow.bytes,
            'spkts': flow.spkts,
            'sbytes': flow.sbytes,
            'appproto': flow.appproto,
            'smac': flow.smac,
            'dmac': flow.dmac,
            'label': label,
            'flow_type': flow.type_,
            'module_labels': {},
        }


        flow_dict = json.dumps(flow_dict)


        if label:
            self.r.zincrby('labels', 1, label)

        flow_dict = {flow.uid: flow_dict}


        flow_dict = json.dumps(flow_dict)

        to_send = {
            'profileid': profileid,
            'twid': twid,
            'flow': flow_dict,
            'stime': flow.starttime,
        }
        to_send = json.dumps(to_send)


        if self.first_flow:
            self.set_input_metadata({'file_start': flow.starttime})
            self.first_flow = False

        self.set_local_network(flow.saddr)


        if flow.type_ != 'arp':
            self.publish('new_flow', to_send)
        return True

    def add_software_to_profile(
        self, profileid, flow
    ):
        """
        Used to associate this profile with it's used software and version
        """
        sw_dict = {
            flow.software: {
                    'version-major': flow.version_major,
                    'version-minor': flow.version_minor,
                    'uid': flow.uid
                }
        }

        if cached_sw := self.get_software_from_profile(profileid):
            if flow.software in cached_sw:


                return

            cached_sw.update(sw_dict)
            self.r.hset(profileid, 'used_software', json.dumps(cached_sw))
        else:

            self.r.hset(profileid, 'used_software', json.dumps(sw_dict))

    def get_total_flows(self):
        """
        gets total flows to process from the db
        """
        return self.r.hget('analysis', 'total_flows')

    def add_out_ssh(
        self,
        profileid,
        twid,
        flow,
    ):
        """
        Store in the DB a SSH request
        All the type of flows that are not netflows are stored in a
        separate hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which
        other type of info is related to that uid
        """
        ssh_flow_dict = {
            'uid': flow.uid,
            'type': flow.type_,
            'version': flow.version,
            'auth_attempts': flow.auth_attempts,
            'auth_success': flow.auth_success,
            'client': flow.client,
            'server': flow.server,
            'cipher_alg': flow.cipher_alg,
            'mac_alg': flow.mac_alg,
            'compression_alg': flow.compression_alg,
            'kex_alg': flow.kex_alg,
            'host_key_alg': flow.host_key_alg,
            'host_key': flow.host_key,
            'stime': flow.starttime,
            'daddr': flow.daddr
        }

        ssh_flow_dict = json.dumps(ssh_flow_dict)


        to_send = {
            'profileid': profileid,
            'twid': twid,
            'flow': ssh_flow_dict,
            'stime': flow.starttime,
            'uid': flow.uid,
        }
        to_send = json.dumps(to_send)

        self.publish('new_ssh', to_send)
        self.print(f'Adding SSH flow to DB: {ssh_flow_dict}', 3, 0)

        self.give_threat_intelligence(profileid, twid, 'dstip', flow.starttime,
                                      flow.uid,
                                      flow.daddr, lookup=flow.daddr)


    def add_out_notice(
        self,
        profileid,
        twid,
        flow,
    ):
        """ " Send notice.log data to new_notice channel to look for self-signed certificates"""
        notice_flow = {
            'type': 'notice',
            'daddr': flow.daddr,
            'sport': flow.sport,
            'dport': flow.dport,
            'note': flow.note,
            'msg': flow.msg,
            'scanned_port': flow.scanned_port,
            'scanning_ip': flow.scanning_ip,
            'stime': flow.starttime,
        }
        notice_flow = json.dumps(
            notice_flow
        )
        to_send = {
            'profileid': profileid,
            'twid': twid,
            'flow': notice_flow,
            'stime': flow.starttime,
            'uid': flow.uid,
        }
        to_send = json.dumps(to_send)
        self.publish('new_notice', to_send)
        self.print(f'Adding notice flow to DB: {notice_flow}', 3, 0)
        self.give_threat_intelligence(
            profileid,
            twid,
            'dstip',
            flow.starttime,
            flow.uid,
            flow.daddr,
            lookup=flow.daddr)


    def add_out_ssl(
        self,
        profileid,
        twid,
        flow
    ):
        """
        Store in the DB an ssl request
        All the type of flows that are not netflows are stored in a separate hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which other type of info is related to that uid
        """
        ssl_flow = {
            'uid': flow.uid,
            'type': flow.type_,
            'version': flow.version,
            'cipher': flow.cipher,
            'resumed': flow.resumed,
            'established': flow.established,
            'cert_chain_fuids': flow.cert_chain_fuids,
            'client_cert_chain_fuids': flow.client_cert_chain_fuids,
            'subject': flow.subject,
            'issuer': flow.issuer,
            'validation_status': flow.validation_status,
            'curve': flow.curve,
            'server_name': flow.server_name,
            'daddr': flow.daddr,
            'dport': flow.dport,
            'stime': flow.starttime,
            'ja3': flow.ja3,
            'ja3s': flow.ja3s,
            'is_DoH': flow.is_DoH,
        }


        ssl_flow = json.dumps(ssl_flow)
        to_send = {
            'profileid': profileid,
            'twid': twid,
            'flow': ssl_flow,
            'stime': flow.starttime,
        }
        to_send = json.dumps(to_send)
        self.publish('new_ssl', to_send)
        self.print(f'Adding SSL flow to DB: {ssl_flow}', 3, 0)



        if not flow.server_name:
            return False


        self.give_threat_intelligence(profileid, twid, 'dstip', flow.starttime,
                                      flow.uid, flow.daddr, lookup=flow.server_name)


        if ipdata := self.getIPData(flow.daddr):
            sni_ipdata = ipdata.get('SNI', [])
        else:
            sni_ipdata = []

        SNI_port = {
            'server_name': flow.server_name,
            'dport': flow.dport
        }

        if SNI_port not in sni_ipdata:


            if dns_resolutions := self.r.hgetall('DNSresolution'):

                for ip, resolution in dns_resolutions.items():
                    resolution = json.loads(resolution)
                    if SNI_port['server_name'] in resolution['domains']:

                        sni_ipdata.append(SNI_port)
                        self.setInfoForIPs(
                            flow.daddr, {'SNI': sni_ipdata}
                        )
                        break


    def getProfileIdFromIP(self, daddr_as_obj):
        """Receive an IP and we want the profileid"""
        try:
            profileid = f'profile{self.separator}{str(daddr_as_obj)}'
            if self.r.sismember('profiles', profileid):
                return profileid
            return False
        except redis.exceptions.ResponseError as inst:
            self.outputqueue.put(
                '00|database|error in addprofileidfromip in database.py'
            )
            self.outputqueue.put(f'00|database|{type(inst)}')
            self.outputqueue.put(f'00|database|{inst}')

    def getProfiles(self):
        """Get a list of all the profiles"""
        profiles = self.r.smembers('profiles')
        return profiles if profiles != set() else {}

    def getTWsfromProfile(self, profileid):
        """
        Receives a profile id and returns the list of all the TW in that profile
        Returns a list of tuples (twid, ts) or an empty list
        """
        return (
            self.r.zrange(f'tws{profileid}', 0, -1, withscores=True)
            if profileid
            else False
        )

    def get_number_of_tws_in_profile(self, profileid) -> int:
        """
        Receives a profile id and returns the number of all the TWs in that profile
        """
        return len(self.getTWsfromProfile(profileid)) if profileid else 0

    def getSrcIPsfromProfileTW(self, profileid, twid):
        """
        Get the src ip for a specific TW for a specific profileid
        """
        return self.r.hget(profileid + self.separator + twid, 'SrcIPs')

    def getDstIPsfromProfileTW(self, profileid, twid):
        """
        Get the dst ip for a specific TW for a specific profileid
        """
        return self.r.hget(profileid + self.separator + twid, 'DstIPs')

    def getT2ForProfileTW(self, profileid, twid, tupleid, tuple_key: str):
        """
        Get T1 and the previous_time for this previous_time, twid and tupleid
        """
        try:
            hash_id = profileid + self.separator + twid
            data = self.r.hget(hash_id, tuple_key)
            if not data:
                return False, False
            data = json.loads(data)
            try:
                (_, previous_two_timestamps) = data[tupleid]
                return previous_two_timestamps
            except KeyError:
                return False, False
        except Exception as e:
            exception_line = sys.exc_info()[2].tb_lineno
            self.outputqueue.put(
                f'01|database|[DB] Error in getT2ForProfileTW in database.py line {exception_line}'
            )

            self.outputqueue.put(f'01|database|[DB] {type(e)}')
            self.outputqueue.put(f'01|database|[DB] {e}')
            self.outputqueue.put(
                f'01|profiler|[Profile] {traceback.format_exc()}'
            )

    def has_profile(self, profileid):
        """Check if we have the given profile"""
        return self.r.sismember('profiles', profileid) if profileid else False

    def get_profiles_len(self) -> int:
        """Return the amount of profiles. Redis should be faster than python to do this count"""
        profiles_n =  self.r.scard('profiles')
        return 0 if not profiles_n else int(profiles_n)

    def get_last_twid_of_profile(self, profileid):
        """Return the last TW id and the starttime of the given profile id"""
        return (
            self.r.zrange(f'tws{profileid}', -1, -1, withscores=True)
            if profileid
            else False
        )

    def getFirstTWforProfile(self, profileid):
        """Return the first TW id and the time for the given profile id"""
        return (
            self.r.zrange(f'tws{profileid}', 0, 0, withscores=True)
            if profileid
            else False
        )

    def getTWofTime(self, profileid, time):
        """
        Return the TW id and the time for the TW that includes the given time.
        The score in the DB is the start of the timewindow, so we should search
        a TW that includes the given time by making sure the start of the TW
        is < time, and the end of the TW is > time.
        """

        try:
            data = self.r.zrangebyscore(
                f'tws{profileid}',
                float('-inf'),
                float(time),
                withscores=True,
                start=0,
                num=-1
            )[-1]

        except IndexError:

            data = self.r.zrangebyscore(
                f'tws{profileid}',
                0,
                float(time),
                withscores=True,
                start=0,
                num=-1
            )

        return data

    def addNewOlderTW(self, profileid, startoftw):
        try:
            """
            Creates or adds a new timewindow that is OLDER than the first we have
            Return the id of the timewindow just created
            """

            try:
                (firstid, firstid_time) = self.getFirstTWforProfile(profileid)[
                    0
                ]


                twid = 'timewindow' + str(
                    int(firstid.split('timewindow')[1]) - 1
                )
            except IndexError:

                pass

            data = {str(twid): float(startoftw)}
            self.r.zadd(f'tws{profileid}', data)
            self.outputqueue.put(
                f'04|database|[DB]: Created and added to DB the new older TW with id {twid}. Time: {startoftw} '
            )


            return twid
        except redis.exceptions.ResponseError as e:
            self.outputqueue.put(
                '01|database|error in addNewOlderTW in database.py', 0, 1
            )
            self.outputqueue.put(f'01|database|{type(e)}', 0, 1)
            self.outputqueue.put(f'01|database|{e}', 0, 1)

    def addNewTW(self, profileid, startoftw):
        try:
            """
            Creates or adds a new timewindow to the list of tw for the given profile
            Add the twid to the ordered set of a given profile
            Return the id of the timewindow just created
            We should not mark the TW as modified here, since there is still no data on it, and it may remain without data.
            """

            try:
                (lastid, lastid_time) = self.get_last_twid_of_profile(profileid)[0]


                twid = 'timewindow' + str(
                    int(lastid.split('timewindow')[1]) + 1
                )
            except IndexError:

                twid = 'timewindow1'

            data = {twid: float(startoftw)}
            self.r.zadd(f'tws{profileid}', data)
            self.outputqueue.put(
                f'04|database|[DB]: Created and added to DB for profile {profileid} on TW with id {twid}. Time: {startoftw} '
            )





            self.update_threat_level(profileid, 'info',  0.5)
            return twid
        except redis.exceptions.ResponseError as e:
            self.outputqueue.put('01|database|Error in addNewTW')
            self.outputqueue.put(f'01|database|{e}')

    def getTimeTW(self, profileid, twid):
        """Return the time when this TW in this profile was created"""


        return self.r.zscore(f'tws{profileid}', twid.encode('utf-8'))

    def getAmountTW(self, profileid):
        """Return the number of tws for this profile id"""
        return self.r.zcard(f'tws{profileid}') if profileid else False

    def getModifiedTWSinceTime(self, time):
        """Return the list of modified timewindows since a certain time"""
        data = self.r.zrangebyscore(
            'ModifiedTW', time, float('+inf'), withscores=True
        )
        return data or []

    def getModifiedProfilesSince(self, time):
        """Returns a set of modified profiles since a certain time and the time of the last modified profile"""
        modified_tws = self.getModifiedTWSinceTime(time)
        if not modified_tws:

            return [], 0

        time_of_last_modified_tw = modified_tws[-1][-1]

        profiles = []
        profiles.extend(
            modified_tw[0].split('_')[1] for modified_tw in modified_tws
        )

        return set(profiles), time_of_last_modified_tw

    def add_mac_addr_to_profile(self, profileid, MAC_info):
        """
        Used to associate this profile with its MAC addr in the 'MAC' key in the db
        format of the MAC key is
            MAC: [ipv4, ipv6, etc.]
        :param MAC_info: dict containing mac address and vendor info
        this functions is called for all macs found in dhcp.log, conn.log, arp.log etc.
        """
        if not profileid:


            return False

        if '0.0.0.0' in profileid:
            return False

        incoming_ip = profileid.split('_')[1]



        if validators.mac_address(incoming_ip):
            return False

        if (
            self.is_gw_mac(MAC_info, incoming_ip)
            and incoming_ip != self.get_gateway_ip()
        ):

            return False

        cached_ip = self.r.hmget('MAC', MAC_info['MAC'])[0]
        if not cached_ip:

            ip = json.dumps([incoming_ip])
            self.r.hset('MAC', MAC_info['MAC'], ip)

            self.r.hset(profileid, 'MAC', json.dumps(MAC_info))
        else:




            cached_ips = json.loads(cached_ip)

            found_ip = cached_ips[-1]


            if incoming_ip in cached_ips:
                return False

            cached_ips = set(cached_ips)

            if validators.ipv6(incoming_ip) and validators.ipv4(found_ip):

                self.set_ipv4_of_profile(profileid, found_ip)
                self.set_ipv6_of_profile(f'profile_{found_ip}', [incoming_ip])
            elif validators.ipv6(found_ip) and validators.ipv4(incoming_ip):

                self.set_ipv6_of_profile(profileid, [found_ip])
                self.set_ipv4_of_profile(f'profile_{found_ip}', incoming_ip)
            elif validators.ipv6(found_ip) and validators.ipv6(incoming_ip):



                ipv6: str = self.r.hmget(profileid, 'IPv6')[0]
                if not ipv6:
                    ipv6 = [found_ip]
                else:

                    ipv6: set = set(json.loads(ipv6))
                    ipv6.add(found_ip)
                    ipv6 = list(ipv6)
                self.set_ipv6_of_profile(profileid, ipv6)


                ipv6: str = self.r.hmget(f'profile_{found_ip}', 'IPv6')[0]
                if not ipv6:
                    ipv6 = [incoming_ip]
                else:

                    ipv6: set = set(json.loads(ipv6))
                    ipv6.add(incoming_ip)

                    ipv6 = list(ipv6)
                self.set_ipv6_of_profile(f'profile_{found_ip}', ipv6)

            else:



                return False


            cached_ips.add(incoming_ip)
            cached_ips = json.dumps(list(cached_ips))
            self.r.hset('MAC', MAC_info['MAC'], cached_ips)

        return True

    def get_mac_addr_from_profile(self, profileid) -> str:
        """
        Returns MAC info about a certain profile or None
        """
        if not profileid:


            return False
        if MAC_info := self.r.hget(profileid, 'MAC'):
            return json.loads(MAC_info)['MAC']
        else:
            return MAC_info

    def add_user_agent_to_profile(self, profileid, user_agent: dict):
        """
        Used to associate this profile with it's used user_agent
        :param user_agent: dict containing user_agent, os_type , os_name and agent_name
        """
        self.r.hset(profileid, 'first user-agent', user_agent)

    def get_user_agents_count(self, profileid) -> int:
        """
        returns the number of unique UAs seen for the given profileid
        """
        return int(self.r.hget(profileid, 'user_agents_count'))


    def add_all_user_agent_to_profile(self, profileid, user_agent: str):
        """
        Used to keep history of past user agents of profile
        :param user_agent: str of user_agent
        """
        if not self.r.hexists(profileid, 'past_user_agents'):

            self.r.hset(profileid, 'past_user_agents', json.dumps([user_agent]))
            self.r.hset(profileid, 'user_agents_count', 1)
        else:

            user_agents = json.loads(self.r.hget(profileid, 'past_user_agents'))
            if user_agent not in user_agents:

                user_agents.append(user_agent)
                self.r.hset(profileid, 'past_user_agents', json.dumps(user_agents))


                user_agents_count: int = self.get_user_agents_count(profileid)
                self.r.hset(profileid, 'user_agents_count', user_agents_count+1 )


    def get_software_from_profile(self, profileid):
        """
        returns a dict with software, major_version, minor_version
        """
        if not profileid:
            return False

        if used_software := self.r.hmget(profileid, 'used_software')[0]:
            used_software = json.loads(used_software)
            return used_software


    def get_first_user_agent(self, profileid) -> str:
        """returns the first user agent used by the given profile"""
        return self.r.hmget(profileid, 'first user-agent')[0]

    def get_user_agent_from_profile(self, profileid) -> str:
        """
        Returns a dict of {'os_name',  'os_type', 'browser': , 'user_agent': }
        used by a certain profile or None
        """
        if not profileid:


            return False

        if user_agent := self.get_first_user_agent(profileid):

            if '{' in user_agent:
                user_agent = json.loads(user_agent)
            return user_agent

    def mark_profile_as_dhcp(self, profileid):
        """
        Used to mark this profile as dhcp server
        """
        if not profileid:


            return False


        profile_in_db = self.r.hmget(profileid, 'dhcp')
        if not profile_in_db:
            return False
        is_dhcp_set = profile_in_db[0]

        if not is_dhcp_set:
            self.r.hset(profileid, 'dhcp', 'true')

    def addProfile(self, profileid, starttime, duration):
        """
        Add a new profile to the DB. Both the list of profiles and the hashmap of profile data
        Profiles are stored in two structures. A list of profiles (index) and individual hashmaps for each profile (like a table)
        Duration is only needed for registration purposes in the profile. Nothing operational
        """
        try:

            if self.r.sismember('profiles', str(profileid)):

                return False

            if not self.should_add(profileid):
                return False

            self.r.sadd('profiles', str(profileid))


            self.r.hset(profileid, 'starttime', starttime)

            self.r.hset(profileid, 'duration', duration)

            self.r.hset(profileid, 'threat_level', 0)
            self.r.hset(profileid, 'confidence', 0.05)

            ip = profileid.split(self.separator)[1]

            self.set_new_ip(ip)

            self.publish('new_profile', ip)
            return True
        except redis.exceptions.ResponseError as inst:
            self.outputqueue.put(
                '00|database|Error in addProfile in database.py'
            )
            self.outputqueue.put(f'00|database|{type(inst)}')
            self.outputqueue.put(f'00|database|{inst}')

    def set_profile_module_label(self, profileid, module, label):
        """
        Set a module label for a profile.
        A module label is a label set by a module, and not
        a groundtruth label
        """
        if not profileid:


            return False
        data = self.get_profile_modules_labels(profileid)
        data[module] = label
        data = json.dumps(data)
        self.r.hset(profileid, 'modules_labels', data)

    def check_TW_to_close(self, close_all=False):
        """
        Check if we should close some TW
        Search in the modifed tw list and compare when they
        were modified with the slips internal time
        """

        sit = self.getSlipsInternalTime()


        modification_time = float(sit) - self.width
        if close_all:

            modification_time = float('inf')

        profiles_tws_to_close = self.r.zrangebyscore(
            'ModifiedTW', 0, modification_time, withscores=True
        )

        for profile_tw_to_close in profiles_tws_to_close:
            profile_tw_to_close_id = profile_tw_to_close[0]
            profile_tw_to_close_time = profile_tw_to_close[1]
            self.print(
                f'The profile id {profile_tw_to_close_id} has to be closed because it was'
                f' last modifed on {profile_tw_to_close_time} and we are closing everything older '
                f'than {modification_time}.'
                f' Current time {sit}. '
                f'Difference: {modification_time - profile_tw_to_close_time}',
                3,
                0,
            )
            self.markProfileTWAsClosed(profile_tw_to_close_id)

    def markProfileTWAsClosed(self, profileid_tw):
        """
        Mark the TW as closed so tools can work on its data
        """
        self.r.sadd('ClosedTW', profileid_tw)
        self.r.zrem('ModifiedTW', profileid_tw)
        self.publish('tw_closed', profileid_tw)

    def markProfileTWAsModified(self, profileid, twid, timestamp):
        """
        Mark a TW in a profile as modified
        This means:
        1- To add it to the list of ModifiedTW
        2- Add the timestamp received to the time_of_last_modification
           in the TW itself
        3- To update the internal time of slips
        4- To check if we should 'close' some TW
        """
        timestamp = time.time()
        data = {
            f'{profileid}{self.separator}{twid}': float(timestamp)
        }
        self.r.zadd('ModifiedTW', data)
        self.publish(
            'tw_modified',
            f'{profileid}:{twid}'
            )

        self.check_TW_to_close()


    def add_tuple(
        self, profileid, twid, tupleid, data_tuple, role, flow
    ):
        """
        Add the tuple going in or out for this profile
        :param tupleid: daddr:dport:proto
        role: 'Client' or 'Server'
        """

        if role == 'Client':
            direction = 'OutTuples'
        elif role == 'Server':
            direction = 'InTuples'

        try:
            self.print(
                f'Add_tuple called with profileid {profileid}, '
                f'twid {twid}, '
                f'tupleid {tupleid}, '
                f'data {data_tuple}',
                3, 0
            )

            profileid_twid = f'{profileid}{self.separator}{twid}'
            tuples = self.r.hget(profileid_twid, direction)

            (symbol_to_add, previous_two_timestamps) = data_tuple
            if not tuples:

                tuples = '{}'

            tuples = json.loads(tuples)
            try:
                tuples[tupleid]

                self.print(
                    f'Not the first time for tuple {tupleid} as an {direction} for '
                    f'{profileid} in TW {twid}. Add the symbol: {symbol_to_add}. '
                    f'Store previous_times: {previous_two_timestamps}. Prev Data: {tuples}',
                    3, 0,
                )

                prev_symbols = tuples[tupleid][0]

                new_symbol = f'{prev_symbols}{symbol_to_add}'


                if len(new_symbol) % 3 == 0:
                    to_send = {
                        'new_symbol': new_symbol,
                        'profileid': profileid,
                        'twid': twid,
                        'tupleid': str(tupleid),
                        'uid': flow.uid,
                        'flow': asdict(flow)
                    }
                    to_send = json.dumps(to_send)
                    self.publish('new_letters', to_send)

                tuples[tupleid] = (new_symbol, previous_two_timestamps)
                self.print(f'\tLetters so far for tuple {tupleid}: {new_symbol}', 3, 0)
                tuples = json.dumps(tuples)
            except (TypeError, KeyError):



                self.print(
                    f'First time for tuple {tupleid} as an {direction} for {profileid} in TW {twid}',
                    3, 0,
                )

                tuples[tupleid] = (symbol_to_add, previous_two_timestamps)

                tuples = json.dumps(tuples)

            self.r.hset(profileid_twid, direction, str(tuples))

            self.markProfileTWAsModified(profileid, twid, flow.starttime)

        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f'01|database|[DB] Error in add_tuple in database.py line {exception_line}'
            )
            self.print(f'01|database|[DB] {traceback.format_exc()}')

    def get_tws_to_search(self, go_back):
        tws_to_search = float('inf')

        if go_back:
            hrs_to_search = float(go_back)
            tws_to_search = self.get_equivalent_tws(hrs_to_search)
        return tws_to_search


    def get_profile_modules_labels(self, profileid):
        """
        Get labels set by modules in the profile.
        """
        if not profileid:


            return {}
        data = self.r.hget(profileid, 'modules_labels')
        data = json.loads(data) if data else {}
        return data

    def add_timeline_line(self, profileid, twid, data, timestamp):
        """Add a line to the timeline of this profileid and twid"""
        if not profileid:


            return
        self.print(f'Adding timeline for {profileid}, {twid}: {data}', 3, 0)
        key = str(
            profileid + self.separator + twid + self.separator + 'timeline'
        )
        data = json.dumps(data)
        mapping = {data: timestamp}
        self.r.zadd(key, mapping)

        self.markProfileTWAsModified(profileid, twid, timestamp='')

    def get_timeline_last_lines(
        self, profileid, twid, first_index: int
    ) -> Tuple[str, int]:
        """Get only the new items in the timeline."""
        if not profileid:


            return [], []
        key = str(
            profileid + self.separator + twid + self.separator + 'timeline'
        )

        last_index = self.r.zcard(key)

        data = self.r.zrange(key, first_index, last_index - 1)
        return data, last_index

    def should_add(self, profileid: str) -> bool:
        """
        determine whether we should add the given profile to the db or not based on the home_network param
        is the user specified the home_network param, make sure the given profile/ip belongs to it before adding
        """

        if not self.home_network:

            return True

        ip = profileid.split(self.separator)[1]
        ip_obj = ipaddress.ip_address(ip)

        return any(ip_obj in network for network in self.home_network)

    def mark_profile_as_gateway(self, profileid):
        """
        Used to mark this profile as dhcp server
        """
        if not profileid:


            return False

        self.r.hset(profileid, 'gateway', 'true')


    def set_ipv6_of_profile(self, profileid, ip: list):
        self.r.hset(profileid, 'IPv6',  json.dumps(ip))

    def set_ipv4_of_profile(self, profileid, ip):
        self.r.hset(profileid, 'IPv4', json.dumps([ip]))
    def get_mac_vendor_from_profile(self, profileid) -> str:
        """
        Returns MAC vendor about a certain profile or None
        """
        if not profileid:


            return False
        if MAC_info := self.r.hget(profileid, 'MAC'):
            return json.loads(MAC_info)['Vendor']
        else:
            return MAC_info

    def get_hostname_from_profile(self, profileid) -> str:
        """
        Returns hostname about a certain profile or None
        """

        if not profileid:


            return False

        return self.r.hget(profileid, 'host_name')

    def add_host_name_to_profile(self, hostname, profileid):
        """
        Adds the given hostname to the given profile
        """
        if not self.get_hostname_from_profile(profileid):
            self.r.hset(profileid, 'host_name', hostname)

    def get_ipv4_from_profile(self, profileid) -> str:
        """
        Returns ipv4 about a certain profile or None
        """
        return self.r.hmget(profileid, 'IPv4')[0] if profileid else False

    def get_ipv6_from_profile(self, profileid) -> str:
        """
        Returns ipv6 about a certain profile or None
        """
        return self.r.hmget(profileid, 'IPv6')[0] if profileid else False

    def get_the_other_ip_version(self, profileid):
        """
        Given an ipv4, returns the ipv6 of the same computer
        Given an ipv6, returns the ipv4 of the same computer
        """
        if not profileid:


            return False
        srcip = profileid.split('_')[-1]
        ip = False
        if validators.ipv4(srcip):
            ip = self.get_ipv6_from_profile(profileid)
        elif validators.ipv6(srcip):
            ip = self.get_ipv4_from_profile(profileid)

        return ip
