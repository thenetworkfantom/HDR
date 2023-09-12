from slips_files.common.slips_utils import utils
import time
import json
from uuid import uuid4

class AlertHandler:
    """
    Helper class for the Redis class in database.py
    Contains all the logic related to setting and retrieving evidence and alerts in the db
    """
    name = 'DB'

    def set_evidence_causing_alert(self, profileid, twid, alert_ID, evidence_IDs: list):
        """
        When we have a bunch of evidence causing an alert,
        we associate all evidence IDs with the alert ID in our database
        this function stores evidence in 'alerts' key only
        :param alert ID: the profileid_twid_ID of the last evidence causing this alert
        :param evidence_IDs: all IDs of the evidence causing this alert
        """
        old_profileid_twid_alerts: dict = self.get_profileid_twid_alerts(profileid, twid)

        alert = {
            alert_ID: json.dumps(evidence_IDs)
        }

        if old_profileid_twid_alerts:


            old_profileid_twid_alerts.update(alert)
            profileid_twid_alerts = json.dumps(old_profileid_twid_alerts)
        else:

            profileid_twid_alerts = json.dumps(alert)


        self.r.hset(f'{profileid}{self.separator}{twid}', 'alerts', profileid_twid_alerts)
        profile_alerts = self.r.hget('alerts', profileid)

        alert_hash = alert_ID.split('_')[-1]
        alert = {
            twid: {
                alert_hash: evidence_IDs
            }
        }
        if not profile_alerts:

            alert = json.dumps(alert)
            self.r.hset('alerts', profileid, alert)
            return



        profile_alerts:dict = json.loads(profile_alerts)

        if twid not in profile_alerts:

            profile_alerts.update(alert)
        else:


            twid_alerts: dict = profile_alerts[twid]
            twid_alerts[alert_hash] = evidence_IDs
            profile_alerts[twid] = twid_alerts

        profile_alerts = json.dumps(profile_alerts)
        self.r.hset('alerts', profileid, profile_alerts)

    def get_evidence_causing_alert(self, profileid, twid, alert_ID) -> list:
        """
        Returns all the IDs of evidence causing this alert
        :param alert_ID: ID of alert to export to warden server
        for example profile_10.0.2.15_timewindow1_4e4e4774-cdd7-4e10-93a3-e764f73af621
        """
        if alerts := self.r.hget(f'{profileid}{self.separator}{twid}', 'alerts'):
            alerts = json.loads(alerts)
            return alerts.get(alert_ID, False)
        return False

    def get_evidence_by_ID(self, profileid, twid, ID):

        evidence = self.getEvidenceForTW(profileid, twid)
        if not evidence:
            return False

        evidence: dict = json.loads(evidence)

        for evidence_details in evidence.values():
            evidence_details = json.loads(evidence_details)
            if evidence_details.get('ID') == ID:

                return evidence_details

    def is_detection_disabled(self, evidence_type: str):
        """
        Function to check if detection is disabled in slips.conf
        """
        for disabled_detection in self.disabled_detections:
            if disabled_detection in evidence_type:
                return True
        return False

    def set_flow_causing_evidence(self, uids: list, evidence_ID):
        self.r.hset("flows_causing_evidence", evidence_ID, json.dumps(uids))

    def get_flows_causing_evidence(self, evidence_ID) -> list:
        uids = self.r.hget("flows_causing_evidence", evidence_ID)
        return json.loads(uids) if uids else []

    def get_victim(self, profileid, attacker):
        saddr = profileid.split("_")[-1]
        if saddr not in attacker:
            return saddr


        return ''

    def setEvidence(
            self,
            evidence_type,
            attacker_direction,
            attacker,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            source_target_tag=False,
            conn_count=False,
            port=False,
            proto=False,
            profileid='',
            twid='',
            uid='',
            victim=''
    ):
        """
        Set the evidence for this Profile and Timewindow.

        evidence_type: determine the type of this evidence. e.g. PortScan, ThreatIntelligence
        attacker_direction: the type of value causing the detection e.g. dstip, srcip, dstdomain, md5, url
        attacker: the actual srcip or dstdomain. e.g. 1.1.1.1 or abc.com
        threat_level: determine the importance of the evidence, available options are:
                        info, low, medium, high, critical
        confidence: determine the confidence of the detection on a scale from 0 to 1.
                        (How sure you are that this is what you say it is.)
        uid: can be a single uid as a str, or a list of uids causing the evidence.
                        needed to get the flow from the database.
        category: what is this evidence category according to IDEA categories
        conn_count: the number of packets/flows/nxdomains that formed this scan/sweep/DGA.
        victim: the ip/domain that was attacked by the attacker param. if not given slips can deduce it.
        this param is usually passed if the saddr is the attacker and slips can't deduce the victim

        source_target_tag:
            this is the IDEA category of the source and dst ip used in the evidence
            if the attacker_direction is srcip this describes the source ip,
            if the attacker_direction is dstip this describes the dst ip.
            supported source and dst types are in the SourceTargetTag section https://idea.cesnet.cz/en/classifications
            this is a keyword/optional argument because it shouldn't be used with dports and sports attacker_direction
        """



        if self.is_detection_disabled(evidence_type):
            return False

        if not twid:
            twid = ''


        evidence_ID = str(uuid4())

        if type(uid) == list:
            uids = list(set(uid))
        else:
            uids = [uid]

        self.set_flow_causing_evidence(uids, evidence_ID)

        if type(threat_level) != str:

            threat_level = utils.threat_level_to_string(threat_level)

        if timestamp:
            timestamp = utils.convert_format(timestamp, utils.alerts_format)

        if not victim:
            victim = self.get_victim(profileid, attacker)

        evidence_to_send = {
            'profileid': str(profileid),
            'twid': str(twid),
            'attacker_direction': attacker_direction,
            'attacker': attacker,
            'evidence_type': evidence_type,
            'description': description,
            'stime': timestamp,
            'uid': uids,
            'confidence': confidence,
            'threat_level': threat_level,
            'category': category,
            'ID': evidence_ID,
            'victim': victim
        }

        if conn_count:
            evidence_to_send['conn_count'] = conn_count


        if source_target_tag:
            evidence_to_send['source_target_tag'] = source_target_tag

        if port:
            evidence_to_send['port'] = port
        if proto:
            evidence_to_send['proto'] = proto

        evidence_to_send = json.dumps(evidence_to_send)




        current_evidence = self.getEvidenceForTW(profileid, twid)
        current_evidence = json.loads(current_evidence) if current_evidence else {}
        should_publish = evidence_ID not in current_evidence.keys()


        current_evidence.update({evidence_ID: evidence_to_send})


        current_evidence = json.dumps(current_evidence)
        self.r.hset(
            f'{profileid}_{twid}', 'Evidence', current_evidence
        )

        self.r.hset(f'evidence{profileid}', twid, current_evidence)



        if should_publish:
            self.r.incr('number_of_evidence', 1)
            self.publish('evidence_added', evidence_to_send)



        if attacker_direction in ('sip', 'srcip'):

            self.update_threat_level(profileid, threat_level, confidence)
        elif attacker_direction in ('dip', 'dstip'):

            self.update_threat_level(f'profile_{attacker}', threat_level, confidence)
        return True


    def init_evidence_number(self):
        """used when the db starts to initialize number of evidence generated by slips """
        self.r.set('number_of_evidence', 0)

    def get_evidence_number(self):
        return self.r.get('number_of_evidence')

    def mark_evidence_as_processed(self, evidence_ID):
        """
        If an evidence was processed by the evidenceprocess, mark it in the db
        """
        self.r.sadd('processed_evidence', evidence_ID)

    def is_evidence_processed(self, evidence_ID):
        return self.r.sismember('processed_evidence', evidence_ID)

    def set_evidence_for_profileid(self, evidence):
        """
        Set evidence for the profile in the same format as json in alerts.json
        """
        evidence = json.dumps(evidence)
        self.r.sadd('Evidence', evidence)

    def deleteEvidence(self, profileid, twid, evidence_ID: str):
        """
        Delete evidence from the database
        """

        current_evidence = self.getEvidenceForTW(profileid, twid)
        current_evidence = json.loads(current_evidence) if current_evidence else {}

        current_evidence.pop(evidence_ID, None)
        current_evidence_json = json.dumps(current_evidence)
        self.r.hset(
            profileid + self.separator + twid,
            'Evidence',
            current_evidence_json,
        )
        self.r.hset(f'evidence{profileid}', twid, current_evidence_json)

        profile_alerts = self.r.hget('alerts', profileid)
        if not profile_alerts:




            time.sleep(0.5)
            return

        profile_alerts:dict = json.loads(profile_alerts)
        try:
            twid_alerts: dict = profile_alerts[twid]
            IDs = False
            hash = False
            for alert_hash, evidence_IDs in twid_alerts.items():
                if evidence_ID in evidence_IDs:
                    IDs = evidence_IDs
                    hash = alert_hash
                break
            else:
                return

            if IDs and hash:
                evidence_IDs = IDs.remove(evidence_ID)
                alert_ID = f'{profileid}_{twid}_{hash}'
                if evidence_IDs:
                    self.set_evidence_causing_alert(
                        profileid, twid, alert_ID, evidence_IDs
                    )

        except KeyError:


            return

    def cache_whitelisted_evidence_ID(self, evidence_ID:str):
        """
        Keep track of whitelisted evidence IDs to avoid showing them in alerts later
        """


        self.r.sadd('whitelisted_evidence', evidence_ID)

    def is_whitelisted_evidence(self, evidence_ID):
        """
        Check if we have the evidence ID as whitelisted in the db to avoid showing it in alerts
        """
        return self.r.sismember('whitelisted_evidence', evidence_ID)

    def remove_whitelisted_evidence(self, all_evidence:str) -> str:
        """
        param all_evidence serialized json dict
        returns a serialized json dict
        """

        all_evidence = json.loads(all_evidence)
        tw_evidence = {}
        for ID,evidence in all_evidence.items():
            if self.is_whitelisted_evidence(ID):
                continue
            tw_evidence[ID] = evidence
        return json.dumps(tw_evidence)

    def get_profileid_twid_alerts(self, profileid, twid) -> dict:
        """
        The format for the returned dict is
            {profile123_twid1_<alert_uuid>: [ev_uuid1, ev_uuid2, ev_uuid3]}
        """
        alerts = self.r.hget(f'{profileid}{self.separator}{twid}', 'alerts')
        if not alerts:
            return {}
        alerts = json.loads(alerts)
        return alerts

    def getEvidenceForTW(self, profileid, twid):
        """Get the evidence for this TW for this Profile"""
        evidence = self.r.hget(profileid + self.separator + twid, 'Evidence')
        if evidence:
            evidence = self.remove_whitelisted_evidence(evidence)
        return evidence

    def update_threat_level(self, profileid, threat_level: str, confidence):
        """
        Update the threat level of a certain profile
        :param threat_level: available options are 'low', 'medium' 'critical' etc
        """

        self.r.hset(profileid, 'threat_level', threat_level)
        now = time.time()
        now = utils.convert_format(now, utils.alerts_format)

        confidence = f'confidence: {confidence}'
        past_threat_levels = self.r.hget(profileid, 'past_threat_levels')

        threat_level_data = (threat_level, now, confidence)
        if past_threat_levels:

            past_threat_levels = json.loads(past_threat_levels)
            latest_threat_level, latest_ts, latest_confidence = past_threat_levels[-1]
            if (
                    latest_threat_level == threat_level
                    and latest_confidence == confidence
            ):


                past_threat_levels[-1] = threat_level_data
            else:

                past_threat_levels.append(threat_level_data)
        else:

            past_threat_levels = [threat_level_data]


        past_threat_levels = json.dumps(past_threat_levels)
        self.r.hset(profileid, 'past_threat_levels', past_threat_levels)



        ip = profileid.split('_')[-1]

        score = utils.threat_levels[threat_level.lower()]
        score_confidence = {
            'score': score,
            'confidence': confidence
        }
        if cached_ip_data := self.getIPData(ip):

            cached_ip_data.update(score_confidence)
            self.rcache.hset('IPsInfo', ip, json.dumps(cached_ip_data))
        else:
            self.rcache.hset('IPsInfo', ip, json.dumps(score_confidence))

