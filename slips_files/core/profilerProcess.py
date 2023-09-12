from slips_files.common.imports import *
from slips_files.core.flows.zeek import Conn, DNS, HTTP, SSL, SSH, DHCP, FTP
from slips_files.core.flows.zeek import Files, ARP, Weird, SMTP, Tunnel, Notice, Software
from slips_files.core.flows.argus import ArgusConn
from slips_files.core.flows.nfdump import NfdumpConn
from slips_files.core.flows.suricata import SuricataFlow, SuricataHTTP, SuricataDNS
from slips_files.core.flows.suricata import SuricataFile,  SuricataTLS, SuricataSSH
from datetime import datetime, timedelta
from slips_files.core.helpers.whitelist import Whitelist
from dataclasses import asdict
import json
import sys
import ipaddress
import traceback
import os
import binascii
import base64
from re import split
from slips_files.common.abstracts import Core
from pprint import pp


class ProfilerProcess(Core):
    """A class to create the profiles for IPs and the rest of data"""
    name = 'Profiler'

    def init(self, profiler_queue=None):

        self.profiler_queue = profiler_queue
        self.timeformat = None
        self.input_type = False
        self.whitelisted_flows_ctr = 0
        self.rec_lines = 0
        self.whitelist = Whitelist(self.output_queue, self.db)

        self.read_configuration()

        self.timeout = 0.0000001
        self.c1 = self.db.subscribe('reload_whitelist')
        self.channels = {
            'reload_whitelist': self.c1,
        }

        self.separators = {
            'zeek': '',
            'suricata': '',
            'nfdump': ',',
            'argus': ',',
            'zeek-tabs': '\t',
            'argus-tabs': '\t'
        }

    def read_configuration(self):
        conf = ConfigParser()
        self.whitelist_path = conf.whitelist_path()
        self.timeformat = conf.ts_format()
        self.analysis_direction = conf.analysis_direction()
        self.label = conf.label()
        self.home_net = conf.get_home_network()
        self.width = conf.get_tw_width_as_float()

    def define_type(self, line):
        """
        Try to define very fast the type of input
        Heuristic detection: dict (zeek from pcap of int), json (suricata), or csv (argus), or TAB separated (conn.log only from zeek)?
        Bro actually gives us json, but it was already coverted into a dict
        in inputProcess
        Outputs can be: zeek, suricata, argus, zeek-tabs
        """
        try:


            try:

                data = line['data']
                file_type = line['type']
            except KeyError:
                self.print('\tData did is not in json format ', 0, 1)
                self.print('\tProblem in define_type()', 0, 1)
                return False

            if file_type in ('stdin', 'external_module'):





                self.input_type = line['line_type']
                self.separator = self.separators[self.input_type]
                return self.input_type




            if type(data) == dict:
                try:
                    _ = data['data']

                    self.input_type = 'zeek-tabs'
                except KeyError:
                    self.input_type = 'zeek'

            else:

                try:


                    data = json.loads(data)
                    if data['event_type']:

                        self.input_type = 'suricata'
                except (ValueError, KeyError):
                    data = str(data)

                    nr_commas = data.count(',')
                    if nr_commas > 3:




                        self.input_type = 'nfdump' if ' ' in data.split(',')[0] else 'argus'
                    elif '->' in data or 'StartTime' in data:
                        self.input_type = 'argus-tabs'
                    else:
                        self.input_type = 'zeek-tabs'

            self.separator = self.separators[self.input_type]
            return self.input_type

        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f'\tProblem in define_type() line {exception_line}', 0, 1
            )
            self.print(traceback.print_exc(),0,1)
            sys.exit(1)

    def define_columns(self, new_line):
        """
        Define the columns for Argus and Zeek-tabs from the line received
        :param new_line: should be the header line of the argus/zeek-tabs file
        """

        line = new_line['data']
        self.column_idx = {}

        supported_fields = {
                'time': 'starttime',
                'endtime':'endtime',
                'appproto': 'appproto',
                'dur':'dur',
                'proto':'proto',
                'srca':'saddr',
                'sport':'sport',
                'dir':'dir',
                'dsta':'daddr',
                'dport':'dport',
                'state':'state',
                'totpkts':'pkts',
                'totbytes':'bytes',
                'srcbytes':'sbytes',
                'dstbytes':'dbytes',
                'srcpkts':'spkts',
                'dstpkts':'dpkts',
            }
        try:
            nline = line.strip().split(self.separator)


            for field in nline:
                for original_field, slips_field in supported_fields.items():
                    if original_field in field.lower():


                        self.column_idx[slips_field] = nline.index(field)
                        break

            return self.column_idx
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f'\tProblem in define_columns() line {exception_line}', 0, 1
            )
            self.print(traceback.print_exc(),0,1)
            sys.exit(1)

    def process_zeek_tabs_input(self, new_line: str) -> None:
        """
        Process the tab line from zeek.
        """
        line = new_line['data']
        line = line.rstrip('\n')



        line = line.split('\t') if '\t' in line else split(r'\s{2,}', line)

        if ts := line[0]:
            starttime = utils.convert_to_datetime(ts)
        else:
            starttime = ''

        def get_value_at(index: int, default_=''):
            try:
                val = line[index]
                return default_ if val == '-' else val
            except IndexError:
                return default_

        uid = get_value_at(1)
        saddr = get_value_at(2, '')
        saddr = get_value_at(3, '')

        if 'conn.log' in new_line['type']:
            self.flow: Conn = Conn(
                starttime,
                get_value_at(1, False),
                get_value_at(2),
                get_value_at(4),

                float(get_value_at(8, 0)),

                get_value_at(6, False),
                get_value_at(7),

                int(get_value_at(3)),
                int(get_value_at(5)),

                int(get_value_at(16, 0)),
                int(get_value_at(18, 0)),

                int(get_value_at(9, 0)),
                int(get_value_at(10, 0)),

                get_value_at(21),
                get_value_at(22),

                get_value_at(11),
                get_value_at(15),
            )


        elif 'dns.log' in new_line['type']:
            self.flow: DNS = DNS(
                starttime,
                get_value_at(1, False),
                get_value_at(2),
                get_value_at(4),

                get_value_at(9),

                get_value_at(11),
                get_value_at(13),
                get_value_at(15),

                get_value_at(21),
                get_value_at(22),
            )

        elif 'http.log' in new_line['type']:
            self.flow: HTTP = HTTP(
                starttime,
                get_value_at(1, False),
                get_value_at(2),
                get_value_at(4),

                get_value_at(7),
                get_value_at(8),
                get_value_at(9),

                get_value_at(11),
                get_value_at(12),

                int(get_value_at(13, 0)),
                int(get_value_at(14, 0)),

                get_value_at(15),
                get_value_at(16),

                get_value_at(28),
                get_value_at(26),

            )

        elif 'ssl.log' in new_line['type']:
            self.flow: SSL = SSL(
                starttime,
                get_value_at(1, False),
                get_value_at(2),
                get_value_at(4),

                get_value_at(6),
                get_value_at(3),
                get_value_at(5),

                get_value_at(7),
                get_value_at(10),

                get_value_at(13),
                get_value_at(14),
                get_value_at(15),

                get_value_at(16),

                get_value_at(17),
                get_value_at(20),
                get_value_at(8),
                get_value_at(9),

                get_value_at(21),
                get_value_at(22),
                get_value_at(23),
            )

        elif 'ssh.log' in new_line['type']:



            auth_success = get_value_at(7)
            if 'T' in auth_success:
                self.flow: SSH = SSH(
                    starttime,
                    get_value_at(1, False),
                    get_value_at(2),
                    get_value_at(4),

                    get_value_at(6),
                    get_value_at(7),
                    get_value_at(8),

                    get_value_at(10),
                    get_value_at(11),
                    get_value_at(12),
                    get_value_at(13),

                    get_value_at(14),
                    get_value_at(15),

                    get_value_at(16),
                    get_value_at(17),
                )
            else:
                self.flow: SSH = SSH(
                    starttime,
                    get_value_at(1, False),
                    get_value_at(2),
                    get_value_at(4),

                    get_value_at(6),
                    '',
                    get_value_at(7),

                    get_value_at(9),
                    get_value_at(10),
                    get_value_at(11),
                    get_value_at(12),

                    get_value_at(13),
                    get_value_at(14),

                    get_value_at(15),
                    get_value_at(16),
                )
        elif 'dhcp.log' in new_line['type']:
            self.flow: DHCP = DHCP(
                starttime,
                get_value_at(1, False),
                get_value_at(2),
                get_value_at(3),

                get_value_at(2),
                get_value_at(3),
                get_value_at(5),

                get_value_at(4),
                get_value_at(8),

            )
        elif 'smtp.log' in new_line['type']:
            self.flow: SMTP = SMTP(
                starttime,
                get_value_at(1, False),
                get_value_at(2),
                get_value_at(4),

                get_value_at(20)
            )
        elif 'tunnel.log' in new_line['type']:
            self.flow: Tunnel = Tunnel(
                starttime,
                get_value_at(1, False),
                get_value_at(2),
                get_value_at(4),

                get_value_at(3),
                get_value_at(5),

                get_value_at(6),
                get_value_at(7),

            )
        elif 'notice.log' in new_line['type']:


            self.flow: Notice = Notice(
                starttime,
                get_value_at(1, False),
                get_value_at(13, '-'),
                get_value_at(4),

                get_value_at(3),
                get_value_at(5, ''),


                get_value_at(10),
                get_value_at(11),

                get_value_at(15),
                get_value_at(13, '-'),

                get_value_at(14),

            )
        elif 'files.log' in new_line['type']:
            self.flow: Files = Files(
                starttime,
                get_value_at(4, False),
                get_value_at(2),
                get_value_at(3),

                get_value_at(13),
                get_value_at(19),

                get_value_at(5),
                get_value_at(7),
                get_value_at(19),

                get_value_at(2),
                get_value_at(3),
            )
        elif 'arp.log' in new_line['type']:
            self.flow: ARP = ARP(
                starttime,
                get_value_at(1, False),
                get_value_at(4),
                get_value_at(5),

                get_value_at(2),
                get_value_at(3),

                get_value_at(6),
                get_value_at(7),

                get_value_at(1),
            )

        elif 'weird' in new_line['type']:
            self.flow: Weird = Weird(
                starttime,
                get_value_at(1, False),
                get_value_at(2),
                get_value_at(4),

                get_value_at(6),
                get_value_at(7),
            )
        else:
            return False
        return True

    def process_zeek_input(self, new_line: dict):
        """
        Process one zeek line(new_line) and extract columns
        (parse them into column_values dict) to send to the database
        """
        line = new_line['data']
        file_type = new_line['type']

        if file_type in ('stdin', 'external_module') and new_line.get('line_type', False) == 'zeek':
            file_type = 'conn'
        else:




            file_type = file_type.split('/')[-1]

        if ts := line.get('ts', False):
            starttime = utils.convert_to_datetime(ts)
        else:
            starttime = ''

        if 'conn' in file_type:
            self.flow: Conn = Conn(
                starttime,
                line.get('uid', False),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),
                line.get('duration', 0),
                line.get('proto',''),
                line.get('service', ''),
                line.get('id.orig_p', ''),
                line.get('id.resp_p', ''),
                line.get('orig_pkts', 0),
                line.get('resp_pkts', 0),
                line.get('orig_bytes', 0),
                line.get('resp_bytes', 0),
                line.get('orig_l2_addr', ''),
                line.get('resp_l2_addr', ''),
                line.get('conn_state', ''),
                line.get('history', ''),
            )



        elif 'dns' in file_type:
            self.flow: DNS = DNS(
                starttime,
                line.get('uid', False),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),
                line.get('query', ''),
                line.get('qclass_name', ''),
                line.get('qtype_name', ''),
                line.get('rcode_name', ''),
                line.get('answers', ''),
                line.get('TTLs', ''),
            )

        elif 'http' in file_type:
            self.flow: HTTP = HTTP(
                starttime,
                line.get('uid', False),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),

                line.get('method', ''),
                line.get('host', ''),
                line.get('uri', ''),
                line.get('version', 0),
                line.get('user_agent', ''),
                line.get('request_body_len', 0),
                line.get('response_body_len', 0),
                line.get('status_code', ''),
                line.get('status_msg', ''),
                line.get('resp_mime_types', ''),
                line.get('resp_fuids', ''),
            )

        elif 'ssl' in file_type:
            self.flow: SSL = SSL(
                starttime,
                line.get('uid', False),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),

                line.get('version', ''),
                line.get('id.orig_p', ','),
                line.get('id.resp_p', ','),

                line.get('cipher', ''),
                line.get('resumed', ''),

                line.get('established', ''),
                line.get('cert_chain_fuids', ''),
                line.get('client_cert_chain_fuids', ''),

                line.get('subject', ''),

                line.get('issuer', ''),
                line.get('validation_status', ''),
                line.get('curve', ''),
                line.get('server_name', ''),

                line.get('ja3', ''),
                line.get('ja3s', ''),
                line.get('is_DoH', 'false'),

            )
        elif 'ssh' in file_type:
            self.flow: SSH = SSH(
                starttime,
                line.get('uid', False),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),

                line.get('version', ''),
                line.get('auth_success', ''),
                line.get('auth_attempts', ''),

                line.get('client', ''),
                line.get('server', ''),
                line.get('cipher_alg', ''),
                line.get('mac_alg', ''),

                line.get('compression_alg', ''),
                line.get('kex_alg', ''),
                line.get('host_key_alg', ''),
                line.get('host_key', ''),


            )
        elif 'dhcp' in file_type:
            self.flow: DHCP = DHCP(
                starttime,
                line.get('uids', []),
                line.get('client_addr', ''),
                line.get('server_addr', ''),

                line.get('client_addr', ''),
                line.get('server_addr', ''),
                line.get('host_name', ''),
                line.get('mac', ''),
                line.get('requested_addr', ''),

            )
        elif 'ftp' in file_type:
            self.flow: FTP = FTP(
                starttime,
                line.get('uids', []),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),

                line.get('data_channel.resp_p', False),
            )
        elif 'smtp' in file_type:
            self.flow: SMTP = SMTP(
                starttime,
                line.get('uid', ''),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),

                line.get('last_reply', '')
            )
        elif 'tunnel' in file_type:
            self.flow: Tunnel = Tunnel(
                starttime,
                line.get('uid', ''),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),

                line.get('id.orig_p', ''),
                line.get('id.resp_p', ''),

                line.get('tunnel_type', ''),
                line.get('action', ''),
            )

        elif 'notice' in file_type:
            self.flow: Notice = Notice(
                starttime,
                line.get('uid', ''),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),

                line.get('id.orig_p', ''),
                line.get('id.resp_p', ''),
                line.get('note', ''),

                line.get('msg', ''),
                line.get('p', ''),
                line.get('src', ''),
                line.get('dst', ''),
            )

        elif 'files.log' in file_type:
            self.flow: Files = Files(
                starttime,
                line.get('conn_uids', [''])[0],
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),

                line.get('seen_bytes', ''),
                line.get('md5', ''),

                line.get('source', ''),
                line.get('analyzers', ''),
                line.get('sha1', ''),

                line.get('tx_hosts',''),
                line.get('rx_hosts',''),
            )
        elif 'arp' in file_type:
            self.flow: ARP = ARP(
                starttime,
                line.get('uid', ''),
                line.get('orig_h', ''),
                line.get('resp_h', ''),

                line.get('src_mac', ''),
                line.get('dst_mac', ''),

                line.get('orig_hw', ''),
                line.get('resp_hw', ''),
                line.get('operation', ''),

            )

        elif 'software' in file_type:
            self.flow: Software = Software(
                starttime,
                line.get('uid', ''),
                line.get('host', ''),
                line.get('resp_h', ''),

                line.get('software_type', ''),

                line.get('unparsed_version', ''),
                line.get('version.major', ''),
                line.get('version.minor', ''),
            )

        elif 'weird' in file_type:
            self.flow: Weird =  Weird(
                starttime,
                line.get('uid', ''),
                line.get('host', ''),
                line.get('resp_h', ''),

                line.get('name', ''),
                line.get('addl', ''),
            )

        else:
            return False
        return True

    def process_argus_input(self, new_line):
        """
        Process the line and extract columns for argus
        """
        line = new_line['data']
        nline = line.strip().split(self.separator)

        def get_value_of(field_name, default_=False):
            """field_name is used to get the index of
             the field from the column_idx dict"""
            try:
                val = nline[self.column_idx[field_name]]
                return val or default_
            except (IndexError, KeyError):
                return default_

        self.flow: ArgusConn = ArgusConn(
            utils.convert_to_datetime(get_value_of('starttime')),
            get_value_of('endtime'),
            get_value_of('dur'),
            get_value_of('proto'),
            get_value_of('appproto'),
            get_value_of('saddr'),
            get_value_of('sport'),
            get_value_of('dir'),
            get_value_of('daddr'),
            get_value_of('dport'),
            get_value_of('state'),
            int(get_value_of('pkts')),
            int(get_value_of('spkts')),
            int(get_value_of('dpkts')),
            int(get_value_of('bytes')),
            int(get_value_of('sbytes')),
            int(get_value_of('dbytes')),
        )
        return True

    def process_nfdump_input(self, new_line):
        """
        Process the line and extract columns for nfdump
        """
        self.separator = ','
        line = new_line['data']
        nline = line.strip().split(self.separator)

        def get_value_at(indx, default_=False):
            try:
                val = nline[indx]
                return val or default_
            except (IndexError, KeyError):
                return default_
        starttime = utils.convert_format(get_value_at(0), 'unixtimestamp')
        endtime = utils.convert_format(get_value_at(1), 'unixtimestamp')
        self.flow: NfdumpConn = NfdumpConn(
            starttime,
            endtime,
            get_value_at(2),
            get_value_at(7),

            get_value_at(3),
            get_value_at(5),

            get_value_at(22),

            get_value_at(4),
            get_value_at(6),

            get_value_at(8),
            get_value_at(11),
            get_value_at(13),

            get_value_at(12),
            get_value_at(14),
        )
        return True

    def get_suricata_answers(self, line: dict) -> list:
        """
        reads the suricata dns answer and extracts the cname and IPs in the dns answerr=
        """
        line = line.get('dns', False)
        if not line:
            return []

        answers: dict = line.get('grouped', False)
        if not answers:
            return []

        cnames: list = answers.get('CNAME', [])
        ips: list = answers.get('A', [])

        return cnames + ips

    def process_suricata_input(self, line) -> None:
        """Read suricata json input and store it in column_values"""


        if type(line) == str:
            line = json.loads(line)
        else:

            line = json.loads(line.get('data', False))

        if not line:
            return

        event_type = line['event_type']
        flow_id = line['flow_id']
        saddr = line['src_ip']
        sport = line['src_port']
        daddr = line['dest_ip']
        dport = line['dest_port']
        proto = line['proto']
        appproto = line.get('app_proto', False)

        try:
            timestamp = utils.convert_to_datetime(line['timestamp'])
        except ValueError:






            timestamp = False

        def get_value_at(field, subfield, default_=False):
            try:
                val = line[field][subfield]
                return val or default_
            except (IndexError, KeyError):
                return default_

        if event_type == 'flow':
            starttime = utils.convert_format(get_value_at('flow', 'start'), 'unixtimestamp')
            endtime = utils.convert_format(get_value_at('flow', 'end'), 'unixtimestamp')
            self.flow: SuricataFlow = SuricataFlow(
                flow_id,
                saddr,
                sport,
                daddr,
                dport,
                proto,
                appproto,

                starttime,
                endtime,

                int(get_value_at('flow', 'pkts_toserver', 0)),
                int(get_value_at('flow', 'pkts_toclient', 0)),

                int(get_value_at('flow', 'bytes_toserver', 0)),
                int(get_value_at('flow', 'bytes_toclient', 0)),

                get_value_at('flow', 'state', ''),
            )

        elif event_type == 'http':
            self.flow: SuricataHTTP = SuricataHTTP(
                timestamp,
                flow_id,
                saddr,
                sport,
                daddr,
                dport,
                proto,
                appproto,
                get_value_at('http', 'http_method', ''),
                get_value_at('http', 'hostname', ''),
                get_value_at('http', 'url', ''),

                get_value_at('http', 'http_user_agent', ''),
                get_value_at('http', 'status', ''),

                get_value_at('http', 'protocol', ''),

                int(get_value_at('http', 'request_body_len', 0)),
                int(get_value_at('http', 'length', 0)),
            )

        elif event_type == 'dns':
            answers: list = self.get_suricata_answers(line)
            self.flow: SuricataDNS = SuricataDNS(
                timestamp,
                flow_id,
                saddr,
                sport,
                daddr,
                dport,
                proto,
                appproto,

                get_value_at('dns', 'rdata', ''),
                get_value_at('dns', 'ttl', ''),
                get_value_at('qtype_name', 'rrtype', ''),
                answers
            )

        elif event_type == 'tls':
            self.flow: SuricataTLS = SuricataTLS(
                timestamp,
                flow_id,
                saddr,
                sport,
                daddr,
                dport,
                proto,
                appproto,

                get_value_at('tls', 'version', ''),
                get_value_at('tls', 'subject', ''),

                get_value_at('tls', 'issuerdn', ''),
                get_value_at('tls', 'sni', ''),

                get_value_at('tls', 'notbefore', ''),
                get_value_at('tls', 'notafter', ''),
                get_value_at('tls', 'sni', ''),
            )

        elif event_type == 'fileinfo':
            self.flow: SuricataFile = SuricataFile(
                timestamp,
                flow_id,
                saddr,
                sport,
                daddr,
                dport,
                proto,
                appproto,
                get_value_at('fileinfo', 'size', ''),

            )
        elif event_type == 'ssh':
            self.flow: SuricataSSH = SuricataSSH(
                timestamp,
                flow_id,
                saddr,
                sport,
                daddr,
                dport,
                proto,
                appproto,
                get_value_at('ssh', 'client', {}).get('software_version', ''),
                get_value_at('ssh', 'client', {}).get('proto_version', ''),
                get_value_at('ssh', 'server', {}).get('software_version', ''),
            )
        else:
            return False
        return True

    def publish_to_new_MAC(self, mac, ip, host_name=False):
        """
        check if mac and ip aren't multicast or link-local
        and publish to new_MAC channel to get more info about the mac
        :param mac: src/dst mac
        :param ip: src/dst ip
        src macs should be passed with srcips, dstmac with dstips
        """
        if not mac or mac in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'):
            return

        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_multicast:
                return
        except ValueError:
            return


        to_send = {
            'MAC': mac,
            'profileid': f'profile_{ip}'
        }
        if host_name:
            to_send['host_name'] = host_name
        self.db.publish('new_MAC', json.dumps(to_send))

    def is_supported_flow(self):

        supported_types = (
            'ssh',
            'ssl',
            'http',
            'dns',
            'conn',
            'flow',
            'argus',
            'nfdump',
            'notice',
            'dhcp',
            'files',
            'arp',
            'ftp',
            'smtp',
            'software',
            'weird',
            'tunnel'
        )

        return bool(
            self.flow.starttime is not None
            and self.flow.type_ in supported_types
        )

    def convert_starttime_to_epoch(self):
        try:


            self.flow.starttime = utils.convert_format(self.flow.starttime, 'unixtimestamp')
        except ValueError:
            self.print(f'We can not recognize time format of self.flow.starttime: {self.flow.starttime}', 0, 1)

    def make_sure_theres_a_uid(self):
        """
        Generates a uid and adds it to the flow if none is found
        """

        if (
                (type(self.flow) == DHCP and not self.flow.uids)
                or
                (type(self.flow) != DHCP and not self.flow.uid)
        ):



            self.flow.uid = base64.b64encode(
                binascii.b2a_hex(os.urandom(9))
            ).decode('utf-8')

    def get_rev_profile(self):
        """
        get the profileid and twid of the daddr at the current starttime,
         not the source address
        """
        if not self.flow.daddr:

            return False, False
        rev_profileid = self.db.getProfileIdFromIP(self.daddr_as_obj)
        if not rev_profileid:
            self.print(
                'The dstip profile was not here... create', 3, 0
            )

            rev_profileid = f'profile_{self.flow.daddr}'
            self.db.addProfile(
                rev_profileid, self.flow.starttime, self.width
            )

            rev_profileid = self.db.getProfileIdFromIP(
                self.daddr_as_obj
            )


        rev_twid = self.db.get_timewindow(self.flow.starttime, rev_profileid)
        return rev_profileid, rev_twid

    def publish_to_new_dhcp(self):
        """
        Publish the GW addr in the new_dhcp channel
        """
        epoch_time = utils.convert_format(self.flow.starttime, 'unixtimestamp')
        self.flow.starttime = epoch_time



        to_send = {
            'profileid': self.profileid,
            'twid': self.db.get_timewindow(epoch_time, self.profileid),
            'flow': asdict(self.flow)
        }
        self.db.publish('new_dhcp', json.dumps(to_send))


    def publish_to_new_software(self):
        """
        Send the whole flow to new_software channel
        """
        epoch_time = utils.convert_format(self.flow.starttime, 'unixtimestamp')
        self.flow.starttime = epoch_time
        to_send = {
            'sw_flow': asdict(self.flow),
            'twid':  self.db.get_timewindow(epoch_time, self.profileid),
        }

        self.db.publish(
            'new_software', json.dumps(to_send)
        )

    def add_flow_to_profile(self):
        """
        This is the main function that takes the columns of a flow and does all the magic to
        convert it into a working data in our system.
        It includes checking if the profile exists and how to put the flow correctly.
        It interprets each column
        """
        try:
            if not hasattr(self, 'flow'):

                return False

            if not self.is_supported_flow():
                return False

            self.make_sure_theres_a_uid()
            self.profileid = f'profile_{self.flow.saddr}'

            try:
                self.saddr_as_obj = ipaddress.ip_address(self.flow.saddr)
                self.daddr_as_obj = ipaddress.ip_address(self.flow.daddr)
            except (ipaddress.AddressValueError, ValueError):

                if self.flow.type_ not in ('software', 'weird'):

                    return False


            if self.whitelist.is_whitelisted_flow(self.flow):
                if 'conn' in self.flow.type_:
                    self.whitelisted_flows_ctr +=1
                return True



            self.print(f'Storing data in the profile: {self.profileid}', 3, 0)
            self.convert_starttime_to_epoch()

            self.twid = self.db.get_timewindow(self.flow.starttime, self.profileid)

            if self.home_net:

                for network in self.home_net:
                    if self.saddr_as_obj in network:

                        self.db.addProfile(
                            self.profileid, self.flow.starttime, self.width
                        )
                        self.store_features_going_out()

                    if (
                        self.analysis_direction == 'all'
                        and self.daddr_as_obj in network
                    ):
                        self.handle_in_flows()

            else:


                self.db.addProfile(self.profileid, self.flow.starttime, self.width)
                self.store_features_going_out()
                if self.analysis_direction == 'all':

                    self.handle_in_flows()

            if self.db.is_cyst_enabled():


                self.print(pp(asdict(self.flow)))

            return True
        except Exception:

            self.print(
                f'Error in add_flow_to_profile Profiler Process. {traceback.format_exc()}'
            ,0,1)
            self.print(traceback.print_exc(),0,1)
            return False

    def handle_conn(self):
        role = 'Client'

        tupleid = f'{self.daddr_as_obj}-{self.flow.dport}-{self.flow.proto}'


        symbol = self.compute_symbol('OutTuples')


        self.db.add_tuple(
            self.profileid, self.twid, tupleid, symbol, role, self.flow
        )

        self.db.add_ips(self.profileid, self.twid, self.flow, role)

        port_type = 'Dst'
        self.db.add_port(self.profileid, self.twid, self.flow, role, port_type)

        port_type = 'Src'
        self.db.add_port(self.profileid, self.twid, self.flow, role, port_type)

        self.db.add_flow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )

        self.publish_to_new_MAC(self.flow.smac, self.flow.saddr)
        self.publish_to_new_MAC(self.flow.dmac, self.flow.daddr)

    def handle_dns(self):
        self.db.add_out_dns(
            self.profileid,
            self.twid,
            self.flow
        )
        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )

    def handle_http(self):
        self.db.add_out_http(
            self.profileid,
            self.twid,
            self.flow,
        )

        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )

    def handle_ssl(self):
        self.db.add_out_ssl(
            self.profileid,
            self.twid,
            self.flow
        )
        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )


    def handle_ssh(self):
        self.db.add_out_ssh(
            self.profileid,
            self.twid,
            self.flow
        )
        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )


    def handle_notice(self):
        self.db.add_out_notice(
                self.profileid,
                self.twid,
                self.flow
        )

        if 'Gateway_addr_identified' in self.flow.note:

            gw_addr = self.flow.msg.split(': ')[-1].strip()
            self.db.set_default_gateway("IP", gw_addr)

        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )

    def handle_ftp(self):
        if used_port := self.flow.used_port:
            self.db.set_ftp_port(used_port)

        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )


    def handle_smtp(self):
        to_send = {
            'flow': asdict(self.flow),
            'profileid': self.profileid,
            'twid': self.twid,
        }
        to_send = json.dumps(to_send)
        self.db.publish('new_smtp', to_send)

        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )


    def handle_in_flows(self):
        """
        Adds a flow for the daddr <- saddr connection
        """


        execluded_flows = ('software')
        if self.flow.type_ in execluded_flows:
            return
        rev_profileid, rev_twid = self.get_rev_profile()
        self.store_features_going_in(rev_profileid, rev_twid)

    def handle_software(self):
        self.db.add_software_to_profile(self.profileid, self.flow)
        self.publish_to_new_software()

        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )


    def handle_dhcp(self):
        if self.flow.smac:

            self.publish_to_new_MAC(
                self.flow.smac or False,
                self.flow.saddr,
                host_name=(self.flow.host_name or False)
            )
        if self.flow.server_addr:
            self.db.store_dhcp_server(self.flow.server_addr)
            self.db.mark_profile_as_dhcp(self.profileid)

        self.publish_to_new_dhcp()
        for uid in self.flow.uids:


            flow = self.flow
            flow.uid = uid
            self.db.add_altflow(
                self.flow,
                self.profileid,
                self.twid,
                'benign'
            )


    def handle_files(self):
        """ Send files.log data to new_downloaded_file channel in vt module to see if it's malicious"""

        to_send = {
            'flow': asdict(self.flow),
            'type': 'suricata' if type(self.flow) == SuricataFile else 'zeek',
            'profileid': self.profileid,
            'twid': self.twid,
        }

        to_send = json.dumps(to_send)
        self.db.publish('new_downloaded_file', to_send)
        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )

    def handle_arp(self):
        to_send = {
            'flow': asdict(self.flow),
            'profileid': self.profileid,
            'twid': self.twid,
        }

        to_send = json.dumps(to_send)
        self.db.publish('new_arp', to_send)

        self.publish_to_new_MAC(
            self.flow.dmac, self.flow.daddr
        )
        self.publish_to_new_MAC(
            self.flow.smac, self.flow.saddr
        )
        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )

    def handle_weird(self):
        """
        handles weird.log zeek flows
        """
        to_send = {
            'profileid': self.profileid,
            'twid': self.twid,
            'flow': asdict(self.flow)
        }
        to_send = json.dumps(to_send)
        self.db.publish('new_weird', to_send)
        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )


    def handle_tunnel(self):
        to_send = {
            'profileid': self.profileid,
            'twid': self.twid,
            'flow': asdict(self.flow)
        }
        to_send = json.dumps(to_send)
        self.db.publish('new_tunnel', to_send)

        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )

    def store_features_going_out(self):
        """
        function for adding the features going out of the profile
        """
        cases = {
            'flow': self.handle_conn,
            'conn': self.handle_conn,
            'nfdump': self.handle_conn,
            'argus': self.handle_conn,
            'dns': self.handle_dns,
            'http': self.handle_http,
            'ssl': self.handle_ssl,
            'ssh': self.handle_ssh,
            'notice': self.handle_notice,
            'ftp': self.handle_ftp,
            'smtp': self.handle_smtp,
            'files': self.handle_files,
            'arp': self.handle_arp,
            'dhcp': self.handle_dhcp,
            'software': self.handle_software,
            'weird': self.handle_weird,
            'tunnel': self.handle_tunnel,
        }
        try:

            cases[self.flow.type_]()
        except KeyError:
            for flow in cases:
                if flow in self.flow.type_:
                    cases[flow]()
            return False



        self.db.markProfileTWAsModified(self.profileid, self.twid, '')

    def store_features_going_in(self, profileid, twid):
        """
        If we have the all direction set , slips creates profiles for each IP, the src and dst
        store features going our adds the conn in the profileA from IP A -> IP B in the db
        this function stores the reverse of this connection. adds the conn in the profileB from IP B <- IP A
        """

        if (
            'flow' not in self.flow.type_
            and 'conn' not in self.flow.type_
            and 'argus' not in self.flow.type_
            and 'nfdump' not in self.flow.type_
        ):
            return
        symbol = self.compute_symbol('InTuples')


        tupleid = f'{self.saddr_as_obj}-{self.flow.dport}-{self.flow.proto}'
        role = 'Server'

        self.db.add_tuple(
            profileid, twid, tupleid, symbol, role, self.flow
        )


        self.db.add_ips(profileid, twid, self.flow, role)
        port_type = 'Src'
        self.db.add_port(profileid, twid, self.flow, role, port_type)


        port_type = 'Dst'
        self.db.add_port(profileid, twid, self.flow, role, port_type)


        self.db.add_flow(
            self.flow,
            profileid=profileid,
            twid=twid,
            label=self.label,
        )
        self.db.markProfileTWAsModified(profileid, twid, '')

    def compute_symbol(
        self,
        tuple_key: str,
    ):
        """
        This function computes the new symbol for the tuple according to the
        original stratosphere ips model of letters
        Here we do not apply any detection model, we just create the letters
        as one more feature twid is the starttime of the flow
        """
        tupleid = f'{self.daddr_as_obj}-{self.flow.dport}-{self.flow.proto}'

        current_duration = self.flow.dur
        current_size = self.flow.bytes

        try:
            current_duration = float(current_duration)
            current_size = int(current_size)
            now_ts = float(self.flow.starttime)
            self.print(
                'Starting compute symbol. Profileid: {}, Tupleid {}, time:{} ({}), dur:{}, size:{}'.format(
                    self.profileid,
                    tupleid,
                    self.twid,
                    type(self.twid),
                    current_duration,
                    current_size,
                ),3,0
            )

            T2 = False
            TD = False


            tto = timedelta(seconds=3600)
            tt1 = 1.05
            tt2 = 1.3
            tt3 = float(5)
            td1 = 0.1
            td2 = float(10)
            ts1 = float(250)
            ts2 = float(1100)



            (last_last_ts, last_ts) = self.db.getT2ForProfileTW(
                self.profileid, self.twid, tupleid, tuple_key
            )


            def compute_periodicity(
                        now_ts: float, last_ts: float, last_last_ts: float
                    ):
                """Function to compute the periodicity"""
                zeros = ''
                if last_last_ts is False or last_ts is False:
                    TD = -1
                    T1 = None
                    T2 = None
                else:

                    T1 = last_ts - last_last_ts


                    T2 = now_ts - last_ts



                    if T2 >= tto.total_seconds():
                        t2_in_hours = T2 / tto.total_seconds()



                        for i in range(int(t2_in_hours)):

                            zeros += '0'


                    try:
                        TD = T2 / T1 if T2 >= T1 else T1 / T2
                    except ZeroDivisionError:
                        TD = 1


                    if TD <= tt1:

                        TD = 1
                    elif TD <= tt2:

                        TD = 2
                    elif TD <= tt3:

                        TD = 3
                    elif TD > tt3:

                        TD = 4
                self.print(
                    'Compute Periodicity: Profileid: {}, Tuple: {}, T1={}, T2={}, TD={}'.format(
                        self.profileid, tupleid, T1, T2, TD
                    ),
                    3,
                    0,
                )
                return TD, zeros

            def compute_duration():
                """Function to compute letter of the duration"""
                if current_duration <= td1:
                    return 1
                elif current_duration > td1 and current_duration <= td2:
                    return 2
                elif current_duration > td2:
                    return 3

            def compute_size():
                """Function to compute letter of the size"""
                if current_size <= ts1:
                    return 1
                elif current_size > ts1 and current_size <= ts2:
                    return 2
                elif current_size > ts2:
                    return 3

            def compute_letter():
                """
                Function to compute letter
                based on the periodicity, size, and dur of the flow
                """


                periodicity_map = {

                    '-1': {


                        '1': {'1': '1', '2': '2', '3': '3'},
                        '2': {'1': '4', '2': '5', '3': '6'},
                        '3': {'1': '7', '2': '8', '3': '9'},
                    },
                    '1': {
                        '1': {'1': 'a', '2': 'b', '3': 'c'},
                        '2': {'1': 'd', '2': 'e', '3': 'f'},
                        '3': {'1': 'g', '2': 'h', '3': 'i'},
                    },
                    '2': {
                        '1': {'1': 'A', '2': 'B', '3': 'C'},
                        '2': {'1': 'D', '2': 'E', '3': 'F'},
                        '3': {'1': 'G', '2': 'H', '3': 'I'},
                    },
                    '3': {
                        '1': {'1': 'r', '2': 's', '3': 't'},
                        '2': {'1': 'u', '2': 'v', '3': 'w'},
                        '3': {'1': 'x', '2': 'y', '3': 'z'},
                    },
                    '4': {
                        '1': {'1': 'R', '2': 'S', '3': 'T'},
                        '2': {'1': 'U', '2': 'V', '3': 'W'},
                        '3': {'1': 'X', '2': 'Y', '3': 'Z'},
                    },
                }
                return periodicity_map[str(periodicity)][str(size)][
                    str(duration)
                ]

            def compute_timechar():
                """Function to compute the timechar"""

                if not isinstance(T2, bool):
                    if T2 <= timedelta(seconds=5).total_seconds():
                        return '.'
                    elif T2 <= timedelta(seconds=60).total_seconds():
                        return ','
                    elif T2 <= timedelta(seconds=300).total_seconds():
                        return '+'
                    elif T2 <= timedelta(seconds=3600).total_seconds():
                        return '*'
                    else:

                        return ''
                else:
                    return ''


            try:

                T2 = now_ts - last_ts if now_ts and last_ts else False

                if T2 < 0:



                    self.print(
                        'Warning: Coming flows are not sorted -> Some time diff are less than zero.',
                        0,
                        2,
                    )
            except TypeError:
                T2 = False



            periodicity, zeros = compute_periodicity(
                now_ts, last_ts, last_last_ts
            )
            duration = compute_duration()

            size = compute_size()

            letter = compute_letter()

            timechar = compute_timechar()

            self.print(
                'Profileid: {}, Tuple: {}, Periodicity: {}, Duration: {}, Size: {}, Letter: {}. TimeChar: {}'.format(
                    self.profileid,
                    tupleid,
                    periodicity,
                    duration,
                    size,
                    letter,
                    timechar,
                ),
                3, 0,
            )

            symbol = zeros + letter + timechar

            return symbol, (last_ts, now_ts)
        except Exception:

            self.print('Error in compute_symbol in Profiler Process.', 0, 1)
            self.print('{}'.format(traceback.format_exc()), 0, 1)

    def shutdown_gracefully(self):




        self.profiler_queue.cancel_join_thread()

    def pre_main(self):
        utils.drop_root_privs()

    def main(self):
        while not self.should_stop():
            try:
                line = self.profiler_queue.get(timeout=3)
            except Exception as e:


                continue


            if line == True:
                continue

            if 'stop' in line:
                self.print(f"Stopping profiler process. Number of whitelisted conn flows: "
                           f"{self.whitelisted_flows_ctr}", 2, 0)

                self.shutdown_gracefully()
                self.print(
                    f'Stopping Profiler Process. Received {self.rec_lines} lines '
                    f'({utils.convert_format(datetime.now(), utils.alerts_format)})',
                    2,
                    0,
                )
                return 1



            self.print(f'< Received Line: {line}', 2, 0)
            self.rec_lines += 1

            if not self.input_type:

                self.define_type(line)

                self.output_queue.put("initialize progress bar")


            if not self.input_type:

                self.print("Can't determine input type.", 5, 6)

            elif self.input_type == 'zeek':

                if self.process_zeek_input(line):

                    self.add_flow_to_profile()

                self.output_queue.put("update progress bar")

            elif self.input_type in ['argus', 'argus-tabs']:



                try:
                    if '-f' in sys.argv and 'argus' in sys.argv:

                        self.define_columns(
                            {
                                'data': "StartTime,Dur,Proto,SrcAddr,Sport,"
                                        "Dir,"
                                        "DstAddr,Dport,State,sTos,dTos,TotPkts,"
                                        "TotBytes,SrcBytes,SrcPkts,Label"
                            }
                        )
                    _ = self.column_idx['starttime']
                    if self.process_argus_input(line):

                        self.add_flow_to_profile()
                    self.output_queue.put("update progress bar")
                except (AttributeError, KeyError):

                    self.define_columns(line)
            elif self.input_type == 'suricata':
                if self.process_suricata_input(line):

                    self.add_flow_to_profile()


                self.output_queue.put("update progress bar")
            elif self.input_type == 'zeek-tabs':

                if self.process_zeek_tabs_input(line):

                    self.add_flow_to_profile()
                self.output_queue.put("update progress bar")
            elif self.input_type == 'nfdump':
                if self.process_nfdump_input(line):
                    self.add_flow_to_profile()
                self.output_queue.put("update progress bar")
            else:
                self.print("Can't recognize input file type.")
                return False




            if self.get_msg('reload_whitelist'):



                self.whitelist.read_whitelist()

        return 1
