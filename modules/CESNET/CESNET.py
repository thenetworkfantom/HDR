from slips_files.common.imports import *
import sys
from ..CESNET.warden_client import Client, read_cfg
import os
import json
import time
import threading
import queue
import ipaddress
import validators
import traceback


class CESNET(Module, multiprocessing.Process):
    name = 'CESNET'
    description = 'Send and receive alerts from warden servers.'
    authors = ['Alya Gomaa']

    def init(self):
        self.read_configuration()
        self.c1 = self.db.subscribe('export_evidence')
        self.channels = {
            'export_evidence' : self.c1,
        }
        self.stop_module = False


    def read_configuration(self):
        """Read importing/exporting preferences from slips.conf"""
        conf = ConfigParser()
        self.send_to_warden = conf.send_to_warden()
        self.receive_from_warden = conf.receive_from_warden()
        if self.receive_from_warden:

            self.poll_delay = conf.poll_delay()

        self.configuration_file = conf.cesnet_conf_file()
        if not os.path.exists(self.configuration_file):
            self.print(
                f"Can't find warden.conf at {self.configuration_file}. "
                f"Stopping module."
            )
            self.stop_module = True

    def remove_private_ips(self, evidence_in_IDEA: dict):
        """
        returns evidence_in_IDEA but without the private IPs
        """

        for type_ in ('Source', 'Target'):
            try:
                alert_field = evidence_in_IDEA[type_]
            except KeyError:

                continue


            for dict_ in alert_field:
                for ip_version in ('IP4', 'IP6'):
                    try:

                        ip = dict_[ip_version][0]
                    except KeyError:

                        continue

                    if ip_version == 'IP4' and (
                        validators.ipv4(ip)
                        and ipaddress.IPv4Address(ip).is_private
                    ):

                        evidence_in_IDEA[type_].remove(dict_)
                    elif (
                        validators.ipv6(ip)
                        and ipaddress.IPv6Address(ip).is_private
                    ):

                        evidence_in_IDEA[type_].remove(dict_)



                    if evidence_in_IDEA[type_] == []:
                        evidence_in_IDEA.pop(type_)

        return evidence_in_IDEA

    def is_valid_alert(self, evidence_in_IDEA) -> bool:
        """
        Make sure we still have a field that contains valid IoCs to export
        """
        return 'Source' in evidence_in_IDEA or 'Target' in evidence_in_IDEA

    def export_evidence(self, evidence: dict):
        """
        Exports evidence to warden server
        """
        threat_level = evidence.get('threat_level')
        if threat_level == 'info':

            return False


        description = evidence['description']
        profileid = evidence['profileid']
        twid = evidence['twid']
        srcip = profileid.split('_')[1]
        evidence_type = evidence['evidence_type']
        attacker_direction = evidence['attacker_direction']
        attacker = evidence['attacker']
        ID = evidence['ID']
        confidence = evidence.get('confidence')
        category = evidence.get('category')
        conn_count = evidence.get('conn_count')
        source_target_tag = evidence.get('source_target_tag')
        port = evidence.get('port')
        proto = evidence.get('proto')

        evidence_in_IDEA = utils.IDEA_format(
            srcip,
            evidence_type,
            attacker_direction,
            attacker,
            description,
            confidence,
            category,
            conn_count,
            source_target_tag,
            port,
            proto,
            ID
        )


        evidence_in_IDEA = self.remove_private_ips(evidence_in_IDEA)


        if not self.is_valid_alert(evidence_in_IDEA):
            return False


        evidence_in_IDEA.update({'Node': self.node_info})


        evidence_in_IDEA['Category'].append('Test')
        evidence_in_IDEA.update({'Category': evidence_in_IDEA['Category']})



        self.print(
            'Uploading 1 event to warden server.', 2, 0
        )


        q = queue.Queue()
        self.sender_thread = threading.Thread(
            target=self.wclient.sendEvents, args=[[evidence_in_IDEA], q]
        )
        self.sender_thread.start()
        self.sender_thread.join()
        result = q.get()

        try:

            self.print(
                f'Done uploading {result["saved"]} events to warden server.\n', 2, 0
            )
        except KeyError:
            self.print(result, 0, 1)

    def import_alerts(self):
        events_to_get = 100

        cat = [
            'Availability',
            'Abusive.Spam',
            'Attempt.Login',
            'Attempt',
            'Information',
            'Fraud.Scam',
            'Information',
            'Fraud.Scam',
        ]


        nocat = []


        tag = []
        notag = []


        group = []
        nogroup = []

        self.print(f'Getting {events_to_get} events from warden server.')
        events = self.wclient.getEvents(
            count=events_to_get,
            cat=cat,
            nocat=nocat,
            tag=tag,
            notag=notag,
            group=group,
            nogroup=nogroup,
        )

        if len(events) == 0:
            self.print('Error getting event from warden server.')
            return False



        src_ips = (
            {}
        )
        for event in events:

            srcips = event.get('Source', [])
            description = event.get('Description', '')
            category = event.get('Category', [])


            node = event.get('Node', [{}])

            if node == []:

                continue

            node_name = node[0].get('Name', '')
            software = node[0].get('SW', [False])[0]
            if not software:


                try:
                    node_name = node[1].get('Name', '')
                    software = node[1].get('SW', [None])[0]
                except IndexError:

                    pass


            for srcip in srcips:

                event_info = {
                    'description': description,
                    'source': f'{node_name}, software: {software}',
                    'threat_level': 'medium',
                    'tags': category[0],
                }



                if 'IP4' in srcip:
                    srcip = srcip['IP4'][0]
                elif 'IP6' in srcip:
                    srcip = srcip['IP6'][0]
                else:
                    srcip = srcip.get('IP', [False])[0]

                if not srcip:
                    continue

                src_ips.update({srcip: json.dumps(event_info)})

        self.db.add_ips_to_IoC(src_ips)

    def pre_main(self):
        utils.drop_root_privs()

        if self.stop_module:
            return 1


        self.wclient = Client(**read_cfg(self.configuration_file))












        self.node_info = [
            {'Name': self.wclient.name, 'Type': ['IPS'], 'SW': ['Slips']}
        ]

    def main(self):
        if self.receive_from_warden:
            last_update = self.db.get_last_warden_poll_time()
            now = time.time()

            if last_update + self.poll_delay < now:
                self.import_alerts()

                self.db.set_last_warden_poll_time(now)


        msg = self.get_msg('export_evidence')
        if msg and self.send_to_warden:
            self.msg_received = True
            evidence = json.loads(msg['data'])
            self.export_evidence(evidence)
