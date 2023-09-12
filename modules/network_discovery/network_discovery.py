from slips_files.common.imports import *
import json
from modules.network_discovery.horizontal_portscan import HorizontalPortscan
from modules.network_discovery.vertical_portscan import VerticalPortscan

class NetworkDiscovery(Module, multiprocessing.Process):
    """
    A class process to find port scans
    This should be converted into a module that wakesup alone when a new alert arrives
    """
    name = 'Network Discovery'
    description = 'Detect Horizonal, Vertical Port scans, ICMP, and DHCP scans'
    authors = ['Sebastian Garcia', 'Alya Gomaa']

    def init(self):
        self.horizontal_ps = HorizontalPortscan(self.db)
        self.vertical_ps = VerticalPortscan(self.db)

        self.fieldseparator = self.db.get_field_separator()

        self.c1 = self.db.subscribe('tw_modified')
        self.c2 = self.db.subscribe('new_notice')
        self.c3 = self.db.subscribe('new_dhcp')
        self.channels = {
            'tw_modified': self.c1,
            'new_notice': self.c2,
            'new_dhcp': self.c3,
        }



        self.cache_det_thresholds = {}
        self.separator = '_'

        self.port_scan_minimum_dports = 5
        self.pingscan_minimum_flows = 5
        self.pingscan_minimum_scanned_ips = 5

        self.time_to_wait_before_generating_new_alert = 25


        self.minimum_requested_addrs = 4

    def shutdown_gracefully(self):

        self.horizontal_ps.combine_evidence()
        self.vertical_ps.combine_evidence()

    def check_icmp_sweep(self, msg, note, profileid, uid, twid, timestamp):
        """
        Use our own Zeek scripts to detect ICMP scans.
        Threshold is on the scrips and it is 25 icmp flows
        """

        if 'TimestampScan' in note:
            evidence_type = 'ICMP-Timestamp-Scan'
        elif 'ICMPAddressScan' in note:
            evidence_type = 'ICMP-AddressScan'
        elif 'AddressMaskScan' in note:
            evidence_type = 'ICMP-AddressMaskScan'
        else:

            return False

        hosts_scanned = int(msg.split('on ')[1].split(' hosts')[0])

        confidence = 1 / (255 - 5) * (hosts_scanned - 255) + 1
        threat_level = 'medium'
        category = 'Recon.Scanning'
        attacker_direction = 'srcip'

        attacker = profileid.split('_')[1]
        source_target_tag = 'Recon'
        description = msg

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=hosts_scanned,
                                 profileid=profileid, twid=twid, uid=uid)

    def check_portscan_type3(self):
        """



        totalpkts = int(data[dport]['totalpkt'])

        if totalpkts > 3:

            evidence_type = 'PortScanType3'

            key = 'dport' + ':' + dport + ':' + evidence_type

            description = 'Too Many Not Estab TCP to same port {} from IP: {}. Amount: {}'.format(dport, profileid.split('_')[1], totalpkts)

            threat_level = 50

            if totalpkts >= 10:

                confidence = 1
            else:

                confidence = totalpkts / 10.0
            self.db.setEvidence(profileid, twid, evidence_type, threat_level, confidence)
            self.print('Too Many Not Estab TCP to same port {} from IP: {}. Amount: {}'.format(dport, profileid.split('_')[1], totalpkts),6,0)
        """

    def check_icmp_scan(self, profileid, twid):

        port_map = {
            '0x0008': 'AddressScan',
            '0x0013': 'TimestampScan',
            '0x0014': 'TimestampScan',
            '0x0017': 'AddressMaskScan',
            '0x0018': 'AddressMaskScan',
        }

        direction = 'Src'
        role = 'Client'
        type_data = 'Ports'
        protocol = 'ICMP'
        state = 'Established'
        sports = self.db.getDataFromProfileTW(
                    profileid, twid, direction, state, protocol, role, type_data
                )
        for sport, sport_info in sports.items():

            attack = port_map.get(sport)
            if not attack:
                return


            scanned_ips = sport_info['dstips']

            amount_of_scanned_ips = len(scanned_ips)

            if amount_of_scanned_ips == 1:

                for scanned_ip, scan_info in scanned_ips.items():
                    icmp_flows_uids = scan_info['uid']
                    number_of_flows = len(icmp_flows_uids)


                    cache_key = f'{profileid}:{twid}:dstip:{scanned_ip}:{sport}:{attack}'
                    prev_flows = self.cache_det_thresholds.get(cache_key, 0)
                    if (
                            number_of_flows % self.pingscan_minimum_flows == 0
                            and prev_flows < number_of_flows
                    ):
                        self.cache_det_thresholds[cache_key] = number_of_flows
                        pkts_sent = scan_info['spkts']
                        timestamp = scan_info['stime']
                        self.set_evidence_icmpscan(
                            amount_of_scanned_ips,
                            timestamp,
                            pkts_sent,
                            protocol,
                            profileid,
                            twid,
                            icmp_flows_uids,
                            attack,
                            scanned_ip=scanned_ip
                        )

            elif amount_of_scanned_ips > 1:


                cache_key = f'{profileid}:{twid}:{attack}'
                prev_scanned_ips = self.cache_det_thresholds.get(cache_key, 0)

                if (
                        amount_of_scanned_ips % self.pingscan_minimum_scanned_ips == 0
                        and prev_scanned_ips < amount_of_scanned_ips
                ):

                    pkts_sent = 0
                    uids = []
                    for scanned_ip, scan_info in scanned_ips.items():

                        pkts_sent += scan_info['spkts']

                        uids.extend(scan_info['uid'])
                        timestamp = scan_info['stime']

                    self.set_evidence_icmpscan(
                            amount_of_scanned_ips,
                            timestamp,
                            pkts_sent,
                            protocol,
                            profileid,
                            twid,
                            uids,
                            attack
                        )
                    self.cache_det_thresholds[cache_key] = amount_of_scanned_ips


    def set_evidence_icmpscan(
            self,
            number_of_scanned_ips,
            timestamp,
            pkts_sent,
            protocol,
            profileid,
            twid,
            icmp_flows_uids,
            attack,
            scanned_ip=False
    ):
        confidence = self.calculate_confidence(pkts_sent)
        attacker_direction = 'srcip'
        evidence_type = attack
        source_target_tag = 'Recon'
        threat_level = 'medium'
        category = 'Recon.Scanning'
        srcip = profileid.split('_')[-1]
        attacker = srcip

        if number_of_scanned_ips == 1:
            description = (
                            f'ICMP scanning {scanned_ip} ICMP scan type: {attack}. '
                            f'Total packets sent: {pkts_sent} over {len(icmp_flows_uids)} flows. '
                            f'Confidence: {confidence}. by Slips'
                        )
            victim = scanned_ip
        else:
            description = (
                f'ICMP scanning {number_of_scanned_ips} different IPs. ICMP scan type: {attack}. '
                f'Total packets sent: {pkts_sent} over {len(icmp_flows_uids)} flows. '
                f'Confidence: {confidence}. by Slips'
            )

            victim = ''

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=pkts_sent,
                                 proto=protocol, profileid=profileid, twid=twid, uid=icmp_flows_uids, victim=victim)


    def set_evidence_dhcp_scan(
            self,
            timestamp,
            profileid,
            twid,
            uids,
            number_of_requested_addrs
    ):
        evidence_type = 'DHCPScan'
        attacker_direction = 'srcip'
        source_target_tag = 'Recon'
        srcip = profileid.split('_')[-1]
        attacker = srcip
        threat_level = 'medium'
        category = 'Recon.Scanning'
        confidence = 0.8
        description = (
            f'Performing a DHCP scan by requesting {number_of_requested_addrs} different IP addresses. '
            f'Threat Level: {threat_level}. '
            f'Confidence: {confidence}. by Slips'
        )

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag,
                                 conn_count=number_of_requested_addrs, profileid=profileid, twid=twid, uid=uids)


    def check_dhcp_scan(self, flow_info):
        """
        Detects DHCP scans, when a client requests 4+ different IPs in the same tw
        """

        flow = flow_info['flow']
        requested_addr = flow['requested_addr']
        if not requested_addr:
            return

        profileid = flow_info['profileid']
        twid = flow_info['twid']

        uids = flow['uids']
        ts = flow['starttime']
        dhcp_flows: dict = self.db.get_dhcp_flows(profileid, twid)

        if dhcp_flows:
            if requested_addr in dhcp_flows:
                return

            self.db.set_dhcp_flow(profileid, twid, requested_addr, uids)
        else:
            self.db.set_dhcp_flow(profileid, twid, requested_addr, uids)
            return

        dhcp_flows: dict = self.db.get_dhcp_flows(profileid, twid)

        number_of_requested_addrs = len(dhcp_flows)
        if number_of_requested_addrs % self.minimum_requested_addrs == 0:
            for uids_list in dhcp_flows.values():
                uids.append(uids_list[0])

            self.set_evidence_dhcp_scan(
                ts,
                profileid,
                twid,
                uids,
                number_of_requested_addrs
            )

    def pre_main(self):
        utils.drop_root_privs()
    def main(self):
        if msg:= self.get_msg('tw_modified'):

            profileid = msg['data'].split(':')[0]
            twid = msg['data'].split(':')[1]

            self.print(
                f'Running the detection of portscans in profile '
                f'{profileid} TW {twid}', 3, 0
            )

            self.horizontal_ps.check(profileid, twid)
            self.vertical_ps.check(profileid, twid)
            self.check_icmp_scan(profileid, twid)

        if msg:= self.get_msg('new_notice'):
            data = msg['data']

            data = json.loads(data)
            profileid = data['profileid']
            twid = data['twid']

            flow = data['flow']

            flow = json.loads(flow)
            timestamp = flow['stime']
            uid = data['uid']
            msg = flow['msg']
            note = flow['note']
            self.check_icmp_sweep(
                msg, note, profileid, uid, twid, timestamp
            )

        if msg:= self.get_msg('new_dhcp'):
            flow = json.loads(msg['data'])
            self.check_dhcp_scan(flow)

