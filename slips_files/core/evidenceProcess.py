from slips_files.common.imports import *
from slips_files.core.helpers.whitelist import Whitelist
from slips_files.core.helpers.notify import Notify
from slips_files.common.abstracts import Core
import json
from datetime import datetime
from os import path
from colorama import Fore, Style
import sys
import os
import time
import platform
import traceback

IS_IN_A_DOCKER_CONTAINER = os.environ.get('IS_IN_A_DOCKER_CONTAINER', False)


class EvidenceProcess(Core):
    """
    A class to process the evidence from the alerts and update the threat level
    It only work on evidence for IPs that were profiled
    This should be converted into a module
    """
    name = 'Evidence'

    def init(self):
        self.whitelist = Whitelist(self.output_queue, self.db)
        self.separator = self.db.get_separator()
        self.read_configuration()
        self.detection_threshold_in_this_width = self.detection_threshold * self.width / 60

        self.db.init_evidence_number()
        if self.popup_alerts:
            self.notify = Notify()
            if self.notify.bin_found:

                self.notify.setup_notifications()
            else:
                self.popup_alerts = False

        self.c1 = self.db.subscribe('evidence_added')
        self.c2 = self.db.subscribe('new_blame')
        self.channels = {
            'evidence_added': self.c1,
            'new_blame': self.c2,
        }


        self.logfile = self.clean_file(self.output_dir, 'alerts.log')
        utils.change_logfiles_ownership(self.logfile.name, self.UID, self.GID)

        self.is_interface = self.is_running_on_interface()


        self.jsonfile = self.clean_file(self.output_dir, 'alerts.json')
        utils.change_logfiles_ownership(self.jsonfile.name, self.UID, self.GID)

        self.print(f'Storing Slips logs in {self.output_dir}')

        self.our_ips = utils.get_own_IPs()

    def read_configuration(self):
        conf = ConfigParser()
        self.width = conf.get_tw_width_as_float()
        self.detection_threshold = conf.evidence_detection_threshold()
        self.print(
            f'Detection Threshold: {self.detection_threshold} '
            f'attacks per minute ({self.detection_threshold * int(self.width) / 60} '
            f'in the current time window width)',2,0,
        )
        self.GID = conf.get_GID()
        self.UID = conf.get_UID()

        self.popup_alerts = conf.popup_alerts()

        if IS_IN_A_DOCKER_CONTAINER:
            self.popup_alerts = False


    def format_evidence_string(self, ip, detection_module, attacker, description):
        """
        Function to format each evidence and enrich it with more data, to be displayed according to each detection module.
        :return : string with a correct evidence displacement
        """
        evidence_string = ''
        dns_resolution_attacker = self.db.get_dns_resolution(attacker)
        dns_resolution_attacker = dns_resolution_attacker.get(
            'domains', []
        )
        dns_resolution_attacker = dns_resolution_attacker[
                                        :3] if dns_resolution_attacker else ''

        dns_resolution_ip = self.db.get_dns_resolution(ip)
        dns_resolution_ip = dns_resolution_ip.get('domains', [])
        if len(dns_resolution_ip) >= 1:
            dns_resolution_ip = dns_resolution_ip[0]
        elif len(dns_resolution_ip) == 0:
            dns_resolution_ip = ''




        if detection_module == 'SSHSuccessful':
            evidence_string = f'Did a successful SSH. {description}'
        else:
            evidence_string = f'Detected {description}'


        return f'{evidence_string}'


    def line_wrap(self, txt):
        """
        is called for evidence that are goinng to be printed in the terminal
        line wraps the given text so it looks nice
        """

        wrap_at = 155

        wrapped_txt = ''
        for indx in range(0, len(txt), wrap_at):
            wrapped_txt += txt[indx:indx+wrap_at]
            wrapped_txt += f'\n{" "*10}'


        wrapped_txt = wrapped_txt[:-11]
        if wrapped_txt.endswith('\n'):
            wrapped_txt = wrapped_txt[:-1]

        return wrapped_txt


    def clean_file(self, output_dir, file_to_clean):
        """
        Clear the file if exists and return an open handle to it
        """
        logfile_path = os.path.join(output_dir, file_to_clean)
        if path.exists(logfile_path):
            open(logfile_path, 'w').close()
        return open(logfile_path, 'a')

    def add_to_json_log_file(self, IDEA_dict: dict, all_uids):
        """
        Add a new evidence line to our alerts.json file in json IDEA format.
        :param IDEA_dict: dict containing 1 alert
        :param all_uids: the uids of the flows causing this evidence
        """
        try:

            IDEA_dict['uids'] = all_uids
            json.dump(IDEA_dict, self.jsonfile)
            self.jsonfile.write('\n')
        except KeyboardInterrupt:
            return True
        except Exception:
            self.print('Error in addDataToJSONFile()')
            self.print(traceback.print_exc(), 0, 1)

    def add_to_log_file(self, data):
        """
        Add a new evidence line to the alerts.log and other log files if logging is enabled.
        """
        try:

            self.logfile.write(data)
            self.logfile.write('\n')
            self.logfile.flush()
        except KeyboardInterrupt:
            return True
        except Exception:
            self.print('Error in addDataToLogFile()')
            self.print(traceback.print_exc(),0,1)

    def get_domains_of_flow(self, flow: dict):
        """Returns the domains of each ip (src and dst) that appeared in this flow"""

        try:
            flow = json.loads(list(flow.values())[0])
        except TypeError:

            return [], []
        domains_to_check_src = []
        domains_to_check_dst = []
        try:
            domains_to_check_src.append(
                self.db.getIPData(flow['saddr'])
                .get('SNI', [{}])[0]
                .get('server_name')
            )
        except (KeyError, TypeError):
            pass
        try:


            src_dns_domains = self.db.get_dns_resolution(flow['saddr'])
            src_dns_domains = src_dns_domains.get('domains', [])

            domains_to_check_src.extend(iter(src_dns_domains))
        except (KeyError, TypeError):
            pass
        try:


            domains_to_check_dst.append(
                self.db.getIPData(flow['daddr'])
                .get('SNI', [{}])[0]
                .get('server_name')
            )
        except (KeyError, TypeError):
            pass

        return domains_to_check_dst, domains_to_check_src

    def show_popup(self, alert_to_log: str):
        """
        Function to display a popup with the alert depending on the OS
        """
        if platform.system() == 'Linux':

            os.system(f'{self.notify_cmd} "Slips" "{alert_to_log}"')
        elif platform.system() == 'Darwin':
            os.system(
                f'osascript -e \'display notification "{alert_to_log}" with title "Slips"\' '
            )


    def format_evidence_causing_this_alert(
        self, all_evidence, profileid, twid, flow_datetime
    ) -> str:
        """
        Function to format the string with all evidence causing an alert
        flow_datetime: time of the last evidence received
        """



        try:
            twid_num = twid.split('timewindow')[1]
            srcip = profileid.split(self.separator)[1]

            twid_start_time = None
            while twid_start_time is None:

                twid_start_time = self.db.getTimeTW(profileid, twid)

            tw_start_time_str = utils.convert_format(twid_start_time,  '%Y/%m/%d %H:%M:%S')

            tw_start_time_datetime = utils.convert_to_datetime(tw_start_time_str)



            delta_width = utils.to_delta(self.width)


            tw_stop_time_datetime = (tw_start_time_datetime + delta_width)

            tw_stop_time_str = utils.convert_format(
                tw_stop_time_datetime,
                 '%Y/%m/%d %H:%M:%S'
            )

            hostname = self.db.get_hostname_from_profile(profileid)

            hostname = hostname or ''
            if hostname:
                hostname = f'({hostname})'

            alert_to_print = (
                f'{Fore.RED}IP {srcip} {hostname} detected as malicious in timewindow {twid_num} '
                f'(start {tw_start_time_str}, stop {tw_stop_time_str}) \n'
                f'given the following evidence:{Style.RESET_ALL}\n'
            )
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f'Problem on format_evidence_causing_this_alert() line {exception_line}',0,1,
            )
            self.print(traceback.print_exc(),0,1)
            return True

        for evidence in all_evidence.values():
            evidence = json.loads(evidence)
            attacker = evidence.get('attacker')
            evidence_type = evidence.get('evidence_type')
            description = evidence.get('description')





            evidence_string = self.format_evidence_string(srcip, evidence_type, attacker, description)
            evidence_string = self.line_wrap(evidence_string)

            alert_to_print += (
                f'\t{Fore.CYAN}- {evidence_string}{Style.RESET_ALL}\n'
            )


        readable_datetime = utils.convert_format(flow_datetime, utils.alerts_format)
        alert_to_print = f'{Fore.RED}{readable_datetime}{Style.RESET_ALL} {alert_to_print}'
        return alert_to_print

    def is_running_on_interface(self):
        return '-i' in sys.argv or self.db.is_growing_zeek_dir()


    def decide_blocking(self, profileid) -> bool:
        """
        Decide whether to block or not and send to the blocking module
        :param ip: IP to block
        """






        ip_to_block = profileid.split('_')[-1]


        if ip_to_block in self.our_ips:
            return False



        blocking_data = {
            'ip': ip_to_block,
            'block': True,
        }
        blocking_data = json.dumps(blocking_data)
        self.db.publish('new_blocking', blocking_data)
        return True

    def mark_as_blocked(
            self, profileid, twid, flow_datetime, accumulated_threat_level, IDEA_dict, blocked=False
    ):
        """
        Marks the profileid and twid as blocked and logs it to alerts.log
        we don't block when running slips on files, we log it in alerts.log only
        :param blocked: bool. if the ip was blocked by the blocking module, we should say so
                    in alerts.log, if not, we should say that we generated an alert
        :param IDEA_dict: the last evidence of this alert, used for logging the blocking
        """
        now = datetime.now()
        now = utils.convert_format(now, utils.alerts_format)
        ip = profileid.split('_')[-1].strip()
        msg = f'{flow_datetime}: Src IP {ip:26}. '
        if blocked:
            self.db.markProfileTWAsBlocked(profileid, twid)

            msg += 'Blocked '
        else:
            msg += 'Generated an alert '

        msg += f'given enough evidence on timewindow {twid.split("timewindow")[1]}. (real time {now})'


        self.add_to_log_file(msg)


        blocked_srcip_dict = {
            'type': 'alert',
            'profileid': profileid,
            'twid': twid,
            'threat_level': accumulated_threat_level,
        }



        IDEA_dict['Format'] = 'Json'
        IDEA_dict['Category'] = 'Alert'
        IDEA_dict['Attach'][0]['Content'] = msg

        self.add_to_json_log_file(IDEA_dict, [])


    def shutdown_gracefully(self):
        self.logfile.close()
        self.jsonfile.close()

    def delete_alerted_evidence(self, profileid, twid, tw_evidence:dict):
        """
        if there was an alert in this tw before, remove the evidence that were part of the past alert
        from the current evidence
        """

        past_alerts = self.db.get_profileid_twid_alerts(profileid, twid)
        if not past_alerts:
            return tw_evidence

        for alert_id, evidence_IDs in past_alerts.items():
            evidence_IDs = json.loads(evidence_IDs)
            for ID in evidence_IDs:
                tw_evidence.pop(ID, None)
        return tw_evidence

    def delete_whitelisted_evidence(self, evidence):
        """
        delete the hash of all whitelisted evidence from the given dict of evidence ids
        """
        res = {}
        for evidence_ID, evidence_info in evidence.items():





            if (
                    not self.db.is_whitelisted_evidence(evidence_ID)
                    and self.db.is_evidence_processed(evidence_ID)
            ):
                res[evidence_ID] = evidence_info
        return res

    def delete_evidence_done_by_others(self, tw_evidence):
        """
        given all the tw evidence, we should only consider evidence that makes this given
        profile malicious, aka evidence of this profile attacking others.
        """
        res = {}
        for evidence_ID, evidence_info in tw_evidence.items():
            evidence_info = json.loads(evidence_info)
            attacker_direction = evidence_info.get('attacker_direction', '')



            if attacker_direction in ('srcip', 'sport', 'srcport'):
                res[evidence_ID] = json.dumps(evidence_info)

        return res


    def get_evidence_for_tw(self, profileid, twid):

        tw_evidence = self.db.getEvidenceForTW(
            profileid, twid
        )
        if not tw_evidence:
            return False

        tw_evidence: dict = json.loads(tw_evidence)
        tw_evidence = self.delete_alerted_evidence(profileid, twid, tw_evidence)
        tw_evidence = self.delete_evidence_done_by_others(tw_evidence)
        tw_evidence = self.delete_whitelisted_evidence(tw_evidence)
        return tw_evidence


    def get_accumulated_threat_level(self, tw_evidence):
        accumulated_threat_level = 0.0

        self.IDs_causing_an_alert = []
        for evidence in tw_evidence.values():
            evidence = json.loads(evidence)


            evidence_type = evidence.get('evidence_type')
            confidence = float(evidence.get('confidence'))
            threat_level = evidence.get('threat_level')
            description = evidence.get('description')
            ID = evidence.get('ID')
            self.IDs_causing_an_alert.append(ID)

            try:
                threat_level = utils.threat_levels[
                    threat_level.lower()
                ]
            except KeyError:
                self.print(
                    f'Error: Evidence of type {evidence_type} has '
                    f'an invalid threat level {threat_level}', 0, 1
                )
                self.print(f'Description: {description}', 0, 1)
                threat_level = 0


            new_threat_level = threat_level * confidence
            self.print(
                f'\t\tWeighted Threat Level: {new_threat_level}', 3, 0
            )
            accumulated_threat_level += new_threat_level
            self.print(
                f'\t\tAccumulated Threat Level: {accumulated_threat_level}', 3, 0,
            )
        return accumulated_threat_level

    def get_last_evidence_ID(self, tw_evidence):
        return list(tw_evidence.keys())[-1]

    def send_to_exporting_module(self, tw_evidence):
        for evidence in tw_evidence.values():
            self.db.publish('export_evidence', evidence)

    def add_hostname_to_alert(self, alert_to_log, profileid, flow_datetime, evidence):


        if hostname := self.db.get_hostname_from_profile(profileid):
            srcip = profileid.split("_")[-1]
            srcip = f'{srcip} ({hostname})'

            srcip = f'{srcip}{" "*(26-len(srcip))}'
            alert_to_log = (
                f'{flow_datetime}: Src IP {srcip}. {evidence}'
            )
        return alert_to_log

    def is_blocking_module_enabled(self) -> bool:
        """
        returns true if slips is running in an interface or growing zeek dir with -p
        or if slips is using custom flows. meaning slips is reading the flows by a custom module not by
        inputprocess. there's no need for -p to enable the blocking
        """

        custom_flows = '-im' in sys.argv or '--input-module' in sys.argv
        return (self.is_running_on_interface() and '-p' not in sys.argv) or custom_flows

    def label_flows_causing_alert(self):
        """Add the label "malicious" to all flows causing this alert in our db """
        for evidence_id in self.IDs_causing_an_alert:
            uids: list = self.db.get_flows_causing_evidence(evidence_id)
            self.db.set_flow_label(uids, 'malicious')

    def main(self):
        while not self.should_stop():
            if msg := self.get_msg('evidence_added'):

                data = json.loads(msg['data'])
                profileid = data.get('profileid')
                srcip = profileid.split(self.separator)[1]
                twid = data.get('twid')
                attacker_direction = data.get(
                    'attacker_direction'
                )
                attacker = data.get(
                    'attacker'
                )
                evidence_type = data.get(
                    'evidence_type'
                )
                description = data.get('description')
                timestamp = data.get('stime')

                all_uids = data.get('uid')

                confidence = data.get('confidence', False)
                threat_level = data.get('threat_level', False)
                category = data.get('category', False)
                conn_count = data.get('conn_count', False)
                port = data.get('port', False)
                proto = data.get('proto', False)
                source_target_tag = data.get('source_target_tag', False)
                evidence_ID = data.get('ID', False)
                victim = data.get('victim', '')




                self.db.mark_evidence_as_processed(evidence_ID)


                if self.whitelist.is_whitelisted_evidence(
                    srcip, attacker, attacker_direction, description, victim
                ):
                    self.db.cache_whitelisted_evidence_ID(evidence_ID)


                    self.db.deleteEvidence(
                        profileid, twid, evidence_ID
                    )
                    continue



                if self.is_running_on_interface():
                    timestamp: datetime = utils.convert_to_local_timezone(timestamp)
                flow_datetime = utils.convert_format(timestamp, 'iso')


                evidence = self.format_evidence_string(srcip, evidence_type, attacker, description)

                IDEA_dict = utils.IDEA_format(
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
                    evidence_ID
                )


                alert_to_log = f'{flow_datetime}: Src IP {srcip:26}. {evidence}'
                alert_to_log = self.add_hostname_to_alert(alert_to_log, profileid, flow_datetime, evidence)


                self.add_to_log_file(alert_to_log)

                self.add_to_json_log_file(IDEA_dict, all_uids)

                self.db.set_evidence_for_profileid(IDEA_dict)
                self.db.publish('report_to_peers', json.dumps(data))

                if tw_evidence := self.get_evidence_for_tw(profileid, twid):






                    accumulated_threat_level = self.get_accumulated_threat_level(tw_evidence)

                    ID = self.get_last_evidence_ID(tw_evidence)


                    profile_already_blocked = self.db.checkBlockedProfTW(profileid, twid)





                    if (
                        accumulated_threat_level >= self.detection_threshold_in_this_width
                        and not profile_already_blocked
                    ):


                        alert_ID = f'{profileid}_{twid}_{ID}'
                        self.db.set_evidence_causing_alert(
                            profileid,
                            twid,
                            alert_ID,
                            self.IDs_causing_an_alert
                        )
                        to_send = {
                            'alert_ID': alert_ID,
                            'profileid': profileid,
                            'twid': twid,
                        }
                        self.db.publish('new_alert', json.dumps(to_send))
                        self.label_flows_causing_alert()
                        self.send_to_exporting_module(tw_evidence)


                        alert_to_print = (
                            self.format_evidence_causing_this_alert(
                                tw_evidence,
                                profileid,
                                twid,
                                flow_datetime,
                            )
                        )
                        self.print(f'{alert_to_print}', 1, 0)

                        if self.popup_alerts:

                            alert_to_print = (
                                alert_to_print.replace(Fore.RED, '')
                                .replace(Fore.CYAN, '')
                                .replace(Style.RESET_ALL, '')
                            )
                            self.notify.show_popup(alert_to_print)


                        blocked = False

                        if self.is_blocking_module_enabled():

                            if self.decide_blocking(profileid):
                                blocked = True

                        self.mark_as_blocked(
                            profileid,
                            twid,
                            flow_datetime,
                            accumulated_threat_level,
                            IDEA_dict,
                            blocked=blocked
                        )

            if msg := self.get_msg('new_blame'):
                self.msg_received = True
                data = msg['data']
                try:
                    data = json.loads(data)
                except json.decoder.JSONDecodeError:
                    self.print(
                        'Error in the report received from p2ptrust module'
                    )
                    return



                key_type = data['key_type']


                key = data['key']


                evaluation_type = data['evaluation_type']


                evaluation = data['evaluation']



                ip_info = {
                    'p2p4slips': evaluation
                }
                ip_info['p2p4slips'].update({'ts': time.time()})
                self.db.store_blame_report(key, evaluation)

                blocking_data = {
                    'ip': key,
                    'block': True,
                    'to': True,
                    'from': True,
                    'block_for': self.width * 2,
                }
                blocking_data = json.dumps(blocking_data)
                self.db.publish('new_blocking', blocking_data)

