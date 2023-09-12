from slips_files.common.imports import *
import ipaddress

class HorizontalPortscan():
    def __init__(self, db):
        self.db = db
        self.cache_det_thresholds = {}
        self.fieldseparator = self.db.get_field_separator()
        self.port_scan_minimum_dips = 5
        self.pending_horizontal_ps_evidence = {}
        self.alerted_once_horizontal_ps = {}

    def calculate_confidence(self, pkts_sent):
        if pkts_sent > 10:
            confidence = 1
        elif pkts_sent == 0:
            return 0.3
        else:
            confidence = pkts_sent / 10.0
        return confidence

    def combine_evidence(self):
        """
        Combines all the evidence in pending_horizontal_ps_evidence into 1 evidence and calls set_evidence
        this function is called every 3 pending ev
        """
        for key, evidence_list in self.pending_horizontal_ps_evidence.items():
            profileid, twid, state, protocol, dport = key.split('-')
            final_evidence_uids = []
            final_pkts_sent = 0
            for evidence in evidence_list:
                timestamp, pkts_sent, evidence_uids, amount_of_dips = evidence
                final_evidence_uids += evidence_uids
                final_pkts_sent += pkts_sent
            self.set_evidence_horizontal_portscan(
                timestamp,
                final_pkts_sent,
                protocol,
                profileid,
                twid,
                final_evidence_uids,
                dport,
                amount_of_dips
            )

        self.pending_horizontal_ps_evidence = {}

    def get_resolved_ips(self, dstips: dict) -> list:
        """
        returns the list of dstips that have dns resolution, we will discard them when checking for
        horizontal portscans
        """
        dstips_to_discard = []

        for dip in dstips:
            dns_resolution = self.db.get_dns_resolution(dip)
            dns_resolution = dns_resolution.get('domains', [])
            if dns_resolution:
                dstips_to_discard.append(dip)
        return dstips_to_discard

    def check(self, profileid, twid):
        def get_uids():
            """
            returns all the uids of flows to this port
            """
            uids = []
            for dip in dstips:
                for uid in dstips[dip]['uid']:
                     uids.append(uid)
            return uids

        saddr = profileid.split(self.fieldseparator)[1]
        try:
            saddr_obj = ipaddress.ip_address(saddr)
            if saddr == '255.255.255.255' or saddr_obj.is_multicast:
                return False
        except ValueError:
            pass


        direction = 'Dst'
        role = 'Client'
        type_data = 'Ports'
        for state in ('Established', 'Not Established'):
            for protocol in ('TCP', 'UDP'):
                dports = self.db.getDataFromProfileTW(
                    profileid, twid, direction, state, protocol, role, type_data
                )


                for dport in dports.keys():
                    dstips: dict = dports[dport]['dstips']
                    for ip in self.get_resolved_ips(dstips):
                        dstips.pop(ip)
                    amount_of_dips = len(dstips)
                    cache_key = f'{profileid}:{twid}:dport:{dport}:HorizontalPortscan'
                    prev_amount_dips = self.cache_det_thresholds.get(cache_key, 0)

                    if (
                        amount_of_dips >= self.port_scan_minimum_dips
                        and prev_amount_dips + 5 <= amount_of_dips
                    ):

                        pkts_sent = 0
                        for dip in dstips:
                            if 'spkts' not in dstips[dip]:
                                pkts_sent += int(dstips[dip]["pkts"])
                            else:
                                pkts_sent += int(dstips[dip]["spkts"])

                        uids: list = get_uids()
                        timestamp = next(iter(dstips.values()))['stime']

                        self.cache_det_thresholds[cache_key] = amount_of_dips

                        if not self.alerted_once_horizontal_ps.get(cache_key, False):
                            self.alerted_once_horizontal_ps[cache_key] = True
                            self.set_evidence_horizontal_portscan(
                                timestamp,
                                pkts_sent,
                                protocol,
                                profileid,
                                twid,
                                uids,
                                dport,
                                amount_of_dips
                            )
                        else:
                            evidence_details = (timestamp, pkts_sent, uids, amount_of_dips)
                            key = f'{profileid}-{twid}-{state}-{protocol}-{dport}'
                            try:
                                self.pending_horizontal_ps_evidence[key].append(evidence_details)
                            except KeyError:
                                self.pending_horizontal_ps_evidence[key] = [evidence_details]
                            if len(self.pending_horizontal_ps_evidence[key]) == 3:
                                self.combine_evidence()

    def set_evidence_horizontal_portscan(
            self,
            timestamp,
            pkts_sent,
            protocol,
            profileid,
            twid,
            uid,
            dport,
            amount_of_dips
    ):
        evidence_type = 'HorizontalPortscan'
        attacker_direction = 'srcip'
        source_target_tag = 'Recon'
        srcip = profileid.split('_')[-1]
        attacker = srcip
        threat_level = 'medium'
        category = 'Recon.Scanning'
        portproto = f'{dport}/{protocol}'
        port_info = self.db.get_port_info(portproto)
        port_info = port_info or ""
        confidence = self.calculate_confidence(pkts_sent)
        description = (
            f'horizontal port scan to port {port_info} {portproto}. '
            f'From {srcip} to {amount_of_dips} unique dst IPs. '
            f'Total packets sent: {pkts_sent}. '
            f'Threat Level: {threat_level}. '
            f'Confidence: {confidence}. by Slips'
        )

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=pkts_sent,
                                 port=dport, proto=protocol, profileid=profileid, twid=twid, uid=uid)
