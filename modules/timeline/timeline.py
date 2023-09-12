from slips_files.common.imports import *
import traceback
import sys
import time
import json


class Timeline(Module, multiprocessing.Process):

    name = 'Timeline'
    description = 'Creates kalipso timeline of what happened in the network based on flows and available data'
    authors = ['Sebastian Garcia']

    def init(self):
        self.separator = self.db.get_field_separator()

        self.c1 = self.db.subscribe('new_flow')
        self.channels = {
            'new_flow': self.c1,
        }

        conf = ConfigParser()
        self.is_human_timestamp = conf.timeline_human_timestamp()
        self.analysis_direction = conf.analysis_direction()


    def process_timestamp(self, timestamp: float) -> str:
        if self.is_human_timestamp:
            timestamp = utils.convert_format(timestamp, utils.alerts_format)
        return str(timestamp)

    def process_flow(self, profileid, twid, flow, timestamp: float):
        """
        Process the received flow  for this profileid and twid
         so its printed by the logprocess later
        """
        timestamp_human = self.process_timestamp(timestamp)

        try:

            uid = next(iter(flow))
            flow_dict = json.loads(flow[uid])
            profile_ip = profileid.split('_')[1]
            dur = round(float(flow_dict['dur']), 3)
            stime = flow_dict['ts']
            saddr = flow_dict['saddr']
            sport = flow_dict['sport']
            daddr = flow_dict['daddr']
            dport = flow_dict['dport']
            proto = flow_dict['proto'].upper()
            dport_name = flow_dict.get('appproto', '')
            if not dport_name:
                dport_name = self.db.get_port_info(
                    f'{str(dport)}/{proto.lower()}'
                )
                if dport_name:
                    dport_name = dport_name.upper()
            else:
                dport_name = dport_name.upper()
            state = flow_dict['state']
            pkts = flow_dict['pkts']
            allbytes = flow_dict['allbytes']
            if type(allbytes) != int:
                allbytes = 0
            spkts = flow_dict['spkts']
            sbytes = flow_dict['sbytes']
            if type(sbytes) != int:
                sbytes = 0



            activity = {}



            if 'TCP' in proto or 'UDP' in proto:
                warning_empty = ''
                critical_warning_dport_name = ''
                if self.analysis_direction == 'all' and str(daddr) == str(
                        profile_ip
                ):
                    dns_resolution = self.db.get_dns_resolution(daddr)
                    dns_resolution = dns_resolution.get('domains', [])


                    if len(dns_resolution) > 3:
                        dns_resolution = dns_resolution[-1]

                    if not dns_resolution:
                        dns_resolution = '????'


                    if not allbytes:
                        warning_empty = 'No data exchange!'


                    if not dport_name:
                        dport_name = '????'
                        critical_warning_dport_name = (
                            'Protocol not recognized by Slips nor Zeek.'
                        )

                    activity = {
                        'timestamp': timestamp_human,
                        'dport_name': dport_name,
                        'preposition': 'from',
                        'dns_resolution': dns_resolution,
                        'saddr': saddr,
                        'daddr':daddr,
                        'dport/proto': f'{str(dport)}/{proto}',
                        'state': state,
                        'warning': warning_empty,
                        'info' : '',
                        'sent': sbytes,
                        'recv': allbytes - sbytes,
                        'tot': allbytes,
                        'duration': dur,
                        'critical warning': critical_warning_dport_name
                    }


                else:

                    if not allbytes:
                        warning_empty = 'No data exchange!'


                    if not dport_name:
                        dport_name = '????'
                        critical_warning_dport_name = (
                            'Protocol not recognized by Slips nor Zeek.'
                        )
                    dns_resolution = self.db.get_dns_resolution(daddr)
                    dns_resolution = dns_resolution.get('domains', [])


                    if len(dns_resolution) > 3:
                        dns_resolution = dns_resolution[-1]

                    if not dns_resolution:
                        dns_resolution = '????'
                    activity = {
                        'timestamp': timestamp_human,
                        'dport_name': dport_name,
                        'preposition': 'to',
                        'dns_resolution': dns_resolution,
                        'daddr': daddr,
                        'dport/proto': f'{str(dport)}/{proto}',
                        'state': state,
                        'warning': warning_empty,
                        'info': '',
                        'sent': sbytes,
                        'recv': allbytes - sbytes,
                        'tot': allbytes,
                        'duration': dur,
                        'critical warning': critical_warning_dport_name
                    }

            elif 'ICMP' in proto:
                extra_info = {}
                warning = ''
                if type(sport) == int:

                    if sport == 11:
                        dport_name = 'ICMP Time Excedded in Transit'

                    elif sport == 3:
                        dport_name = 'ICMP Destination Net Unreachable'

                    elif sport == 8:
                        dport_name = 'PING echo'

                    else:
                        dport_name = 'ICMP Unknown type'
                        extra_info =  {
                            'type': f'0x{str(sport)}',
                        }

                elif type(sport) == str:

                    if '0x0008' in sport:
                        dport_name = 'PING echo'
                    elif '0x0103' in sport:
                        dport_name = 'ICMP Host Unreachable'
                    elif '0x0303' in sport:
                        dport_name = 'ICMP Port Unreachable'
                        warning = f'unreachable port is {int(dport, 16)}'
                    elif '0x000b' in sport:
                        dport_name = ''
                    elif '0x0003' in sport:
                        dport_name = 'ICMP Destination Net Unreachable'
                    else:
                        dport_name = 'ICMP Unknown type'

                activity = {
                            'timestamp': timestamp_human,
                            'dport_name': dport_name,
                            'preposition': 'from',
                            'saddr': saddr,
                            'size': allbytes,
                            'duration': dur,
                        }

                extra_info.update({
                     'dns_resolution':'',
                     'daddr': daddr,
                     'dport/proto': f'{sport}/ICMP',
                     'state': '',
                     'warning' : warning,
                     'sent' :'',
                     'recv' :'',
                     'tot' :'',
                     'critical warning' : '',
                })

                activity.update(extra_info)

            elif 'IGMP' in proto:
                dport_name = 'IGMP'
                activity = {
                    'timestamp': timestamp_human,
                    'dport_name': dport_name,
                    'preposition': 'from',
                    'saddr': saddr,
                    'size': allbytes,
                    'duration': dur,
                }




            time.sleep(0.05)
            alt_flow: dict = self.db.get_altflow_from_uid(
                profileid, twid, uid
            )

            alt_activity = {}
            http_data = {}
            if alt_flow:
                flow_type = alt_flow['type_']
                self.print(
                    f"Received an altflow of type {flow_type}: {alt_flow}",
                    3, 0
                )
                if 'dns' in flow_type:
                    answer = alt_flow['answers']
                    if 'NXDOMAIN' in alt_flow['rcode_name']:
                        answer = 'NXDOMAIN'
                    dns_activity = {
                        'query': alt_flow['query'],
                        'answers': answer
                    }
                    alt_activity = {
                        'info': dns_activity,
                        'critical warning':'',
                    }
                elif flow_type == 'http':
                    http_data_all = {
                        'Request': alt_flow['method']
                        + ' http://'
                        + alt_flow['host']
                        + alt_flow['uri'],
                        'Status Code': str(alt_flow['status_code'])
                        + '/'
                        + alt_flow['status_msg'],
                        'MIME': str(alt_flow['resp_mime_types']),
                        'UA': alt_flow['user_agent'],
                    }

                    http_data = {
                        k: v
                        for k, v in http_data_all.items()
                        if v != '' and v != '/'
                    }
                    alt_activity = {'info': http_data}
                elif flow_type == 'ssl':
                    if alt_flow['validation_status'] == 'ok':
                        validation = 'Yes'
                        resumed = 'False'
                    elif (
                        not alt_flow['validation_status']
                        and alt_flow['resumed'] is True
                    ):



                        validation = '??'
                        resumed = 'True'
                    else:

                        validation = 'No'
                        resumed = 'False'

                    subject = alt_flow['subject'].split(',')[0] if alt_flow[
                        'subject'] else '????'

                    ssl_activity = {
                        'server_name': subject,
                        'trusted': validation,
                        'resumed': resumed,
                        'version': alt_flow['version'],
                        'dns_resolution': alt_flow['server_name']
                    }
                    alt_activity = {'info': ssl_activity}
                elif flow_type == 'ssh':
                    success = 'Successful' if alt_flow[
                        'auth_success'] else 'Not Successful'
                    ssh_activity = {
                        'login': success,
                        'auth_attempts': alt_flow['auth_attempts'],
                        'client': alt_flow['client'],
                        'server': alt_flow['client'],
                    }
                    alt_activity = {'info': ssh_activity}

            elif activity:
                alt_activity = {'info': ''}


            activity.update(alt_activity)
            if activity:
                self.db.add_timeline_line(
                    profileid, twid, activity, timestamp
                )
            self.print(
                f'Activity of Profileid: {profileid}, TWid {twid}: '
                f'{activity}', 3, 0
            )


        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f'Problem on process_flow() line {exception_line}', 0, 1
            )
            self.print(traceback.print_exc(),0,1)
            return True

    def pre_main(self):
        utils.drop_root_privs()

    def main(self):

        if msg:= self.get_msg('new_flow'):
            mdata = msg['data']

            mdata = json.loads(mdata)
            profileid = mdata['profileid']
            twid = mdata['twid']
            flow = mdata['flow']
            timestamp = mdata['stime']
            flow = json.loads(flow)
            self.process_flow(
                profileid, twid, flow, timestamp
            )
