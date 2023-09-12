from slips_files.common.imports import *
import sys
import traceback
import time
import ipaddress
import json
import threading

class VerticalPortscan():
    def __init__(self, db):
        self.db = db
        self.cache_det_thresholds = {}
        self.fieldseparator = self.db.get_field_separator()
        self.port_scan_minimum_dports = 5
        self.pending_vertical_ps_evidence = {}
        self.alerted_once_vertical_ps = {}


    def combine_evidence(self):
        for key, evidence_list in self.pending_vertical_ps_evidence.items():
            profileid, twid, state, protocol, dstip = key.split('-')
            final_evidence_uids = []
            final_pkts_sent = 0
            for evidence in evidence_list:
                timestamp, pkts_sent, evidence_uids, amount_of_dports = evidence
                final_evidence_uids += evidence_uids
                final_pkts_sent += pkts_sent

            self.set_evidence_vertical_portscan(
                timestamp,
                final_pkts_sent,
                protocol,
                profileid,
                twid,
                final_evidence_uids,
                amount_of_dports,
                dstip
            )

        self.pending_vertical_ps_evidence = {}

    def set_evidence_vertical_portscan(
            self,
            timestamp,
            pkts_sent,
            protocol,
            profileid,
            twid,
            uid,
            amount_of_dports,
            dstip
    ):
        attacker_direction = 'srcip'
        evidence_type = 'VerticalPortscan'
        source_target_tag = 'Recon'
        threat_level = 'medium'
        category = 'Recon.Scanning'
        srcip = profileid.split('_')[-1]
        attacker = srcip
        confidence = self.calculate_confidence(pkts_sent)
        description = (
                        f'new vertical port scan to IP {dstip} from {srcip}. '
                        f'Total {amount_of_dports} dst {protocol} ports were scanned. '
                        f'Total packets sent to all ports: {pkts_sent}. '
                        f'Confidence: {confidence}. by Slips'
                    )
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=pkts_sent,
                                 proto=protocol, profileid=profileid, twid=twid, uid=uid, victim=dstip)


    def calculate_confidence(self, pkts_sent):
        if pkts_sent > 10:
            confidence = 1
        elif pkts_sent == 0:
            return 0.3
        else:

            confidence = pkts_sent / 10.0
        return confidence

    def check(self, profileid, twid):
        direction = 'Dst'
        role = 'Client'
        type_data = 'IPs'
        evidence_type = 'VerticalPortscan'
        for state in ('Not Established', 'Established'):
            for protocol in ('TCP', 'UDP'):
                dstips = self.db.getDataFromProfileTW(
                    profileid, twid, direction, state, protocol, role, type_data
                )

                for dstip in dstips.keys():

                    dstports: dict = dstips[dstip]['dstports']
                    amount_of_dports = len(dstports)
                    cache_key = f'{profileid}:{twid}:dstip:{dstip}:{evidence_type}'
                    prev_amount_dports = self.cache_det_thresholds.get(cache_key, 0)

                    if (
                            amount_of_dports >= self.port_scan_minimum_dports
                            and prev_amount_dports+5 <= amount_of_dports
                    ):

                        pkts_sent = sum(dstports[dport] for dport in dstports)
                        uid = dstips[dstip]['uid']
                        timestamp = dstips[dstip]['stime']
                        self.cache_det_thresholds[cache_key] = amount_of_dports

                        if not self.alerted_once_vertical_ps.get(cache_key, False):

                            self.alerted_once_vertical_ps[cache_key] = True
                            self.set_evidence_vertical_portscan(
                                timestamp,
                                pkts_sent,
                                protocol,
                                profileid,
                                twid,
                                uid,
                                amount_of_dports,
                                dstip
                            )
                        else:
                            evidence_details = (timestamp, pkts_sent, uid, amount_of_dports)
                            key = f'{profileid}-{twid}-{state}-{protocol}-{dstip}'
                            try:
                                self.pending_vertical_ps_evidence[key].append(evidence_details)
                            except KeyError:

                                self.pending_vertical_ps_evidence[key] = [evidence_details]


                            if len(self.pending_vertical_ps_evidence[key]) == 3:
                                self.combine_evidence()
