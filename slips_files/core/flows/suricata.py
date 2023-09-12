from dataclasses import dataclass
from slips_files.common.slips_utils import utils
from datetime import datetime, timedelta
import json

"""
#     suricata available event_type values:
#     -flow
#     -tls
#     -http
#     -dns
#     -alert
#     -fileinfo
#     -stats (only one line - it is conclusion of entire capture)
"""


@dataclass
class SuricataFlow:
    uid: str
    saddr: str
    sport: str
    daddr: str
    dport: str
    proto: str
    appproto: str
    starttime: str
    endtime: str
    spkts: int
    dpkts: int
    sbytes: int
    dbytes: int
    state: str
    smac: str = ''
    dmac: str = ''
    dir_: str = '->'
    type_: str = 'conn'

    def __post_init__(self):
        self.dur = (
               utils.convert_to_datetime(self.endtime)
               - utils.convert_to_datetime(self.starttime)
            ).total_seconds() or 0
        self.pkts = self.dpkts + self.spkts
        self.bytes = self.dbytes + self.sbytes

@dataclass
class SuricataHTTP:
    starttime: str
    uid: str
    saddr: str
    sport: str
    daddr: str
    dport: str
    proto: str
    appproto: str
    method: str
    host: str
    uri: str
    user_agent: str
    status_code: str
    version: str
    request_body_len: int
    response_body_len: int
    status_msg: str = ''
    resp_mime_types: str = ''
    resp_fuids: str = ''
    type_:str = 'http'

@dataclass
class SuricataDNS:
    starttime: str
    uid: str
    saddr: str
    sport: str
    daddr: str
    dport: str
    proto: str
    appproto: str
    query: str
    TTLs: str
    qtype_name: str
    answers: list
    qclass_name: str = ''
    rcode_name: str = ''
    type_: str = 'dns'


@dataclass
class SuricataTLS:
    starttime: str
    uid: str
    saddr: str
    sport: str
    daddr: str
    dport: str
    proto: str
    appproto: str
    sslversion: str
    subject: str
    issuer: str
    server_name: str
    notbefore: str
    notafter: str
    type_: str = 'ssl'


@dataclass
class SuricataFile:
    starttime: str
    uid: str
    saddr: str
    sport: str
    daddr: str
    dport: str
    proto: str
    appproto: str
    size: int
    type_: str = 'files'
    md5: str = ''
    sha1: str = ''
    source: str =''
    analyzers: str =''
    tx_hosts: str = ''
    rx_hosts: str = ''

@dataclass
class SuricataSSH:
    starttime: str
    uid: str
    saddr: str
    sport: str
    daddr: str
    dport: str
    proto: str
    appproto: str
    client: str
    version: str
    server: str
    auth_success: str = ''
    auth_attempts: str = ''
    cipher_alg: str = ''
    mac_alg: str = ''
    kex_alg: str = ''
    compression_alg: str = ''
    host_key_alg: str = ''
    host_key: str = ''

    type_: str = 'ssh'

