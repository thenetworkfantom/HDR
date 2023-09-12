from slips_files.common.imports import *
import sys
import base64
import time
import binascii
import os
import subprocess
import json
import shutil

class LeakDetector(Module, multiprocessing.Process):
    name = 'Leak Detector'
    description = 'Detect leaks of data in the traffic'
    authors = ['HackTheHeck']

    def init(self):
        try:
            self.pcap = utils.sanitize(sys.argv[sys.argv.index('-f') + 1])
        except ValueError:
            pass
        self.yara_rules_path = 'modules/leak_detector/yara_rules/rules/'
        self.compiled_yara_rules_path = (
            'modules/leak_detector/yara_rules/compiled/'
        )
        self.bin_found = False
        if self.is_yara_installed():
            self.bin_found = True


    def is_yara_installed(self) -> bool:
        """
        Checks if notify-send bin is installed
        """
        cmd = 'yara -h > /dev/null 2>&1'
        returncode = os.system(cmd)
        if returncode in [256, 0]:
            return True

        self.print("yara is not installed. install it using:\nsudo apt-get install yara")
        return False


    def fix_json_packet(self, json_packet):
        """
        in very large pcaps, tshark gets killed before it's done processing,
        but the first packet info is printed in a corrupted json format
        this function fixes the printed packet
        """
        json_packet = json_packet.replace("Killed", '')
        json_packet += '}]'
        try:
            return json.loads(json_packet)
        except json.decoder.JSONDecodeError:
            return False

    def get_packet_info(self, offset: int):
        """
        Parse pcap and determine the packet at this offset
        returns  a tuple with packet info (srcip, dstip, proto, sport, dport, ts) or False if not found
        """
        offset = int(offset)
        with open(self.pcap, 'rb') as f:
            f.read(24)
            packet_number = 0
            packet_data_length = True
            while packet_data_length:
                packet_number += 1
                start_offset = f.tell() + 1
                packet_header = f.read(16)
                packet_data_length = packet_header[8:12][::-1]
                packet_length_in_decimal = int.from_bytes(
                    packet_data_length, 'big'
                )


                f.read(packet_length_in_decimal)
                end_offset = f.tell()
                if offset <= end_offset and offset >= start_offset:


                    cmd = f'tshark -r "{self.pcap}" -T json -Y frame.number=={packet_number}'
                    tshark_proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.PIPE,
                        shell=True
                    )

                    result, error = tshark_proc.communicate()
                    if error:
                        self.print (f"tshark error {tshark_proc.returncode}: {error.strip()}")
                        return

                    json_packet = result.decode()

                    try:
                        json_packet = json.loads(json_packet)
                    except json.decoder.JSONDecodeError:
                        json_packet = self.fix_json_packet(json_packet)

                    if json_packet:

                        json_packet = json_packet[0]['_source']['layers']


                        used_protocols = json_packet['frame'][
                            'frame.protocols'
                        ]
                        ip_family = 'ipv6' if 'ipv6' in used_protocols else 'ip'
                        if 'tcp' in used_protocols:
                            proto = 'tcp'
                        elif 'udp' in used_protocols:
                            proto = 'udp'
                        else:

                            return

                        try:
                            ts = json_packet['frame']['frame.time_epoch']
                            srcip = json_packet[ip_family][f'{ip_family}.src']
                            dstip = json_packet[ip_family][f'{ip_family}.dst']
                            sport = json_packet[proto][f'{proto}.srcport']
                            dport = json_packet[proto][f'{proto}.dstport']
                        except KeyError:
                            return

                        return (srcip, dstip, proto, sport, dport, ts)

        return False

    def set_evidence_yara_match(self, info: dict):
        """
        This function is called when yara finds a match
        :param info: a dict with info about the matched rule, example keys 'vars_matched', 'index',
        'rule', 'srings_matched'
        """
        rule = info.get('rule').replace('_', ' ')
        offset = info.get('offset')

        strings_matched = info.get('strings_matched')

        if packet_info := self.get_packet_info(offset):
            srcip, dstip, proto, sport, dport, ts = (
                packet_info[0],
                packet_info[1],
                packet_info[2],
                packet_info[3],
                packet_info[4],
                packet_info[5],
            )

            portproto = f'{dport}/{proto}'
            port_info = self.db.get_port_info(portproto)


            uid = base64.b64encode(binascii.b2a_hex(os.urandom(9))).decode(
                'utf-8'
            )
            src_profileid = f'profile_{srcip}'
            dst_profileid = f'profile_{dstip}'


            time.sleep(4)

            if self.db.has_profile(src_profileid):
                attacker_direction = 'dstip'
                victim = srcip
                profileid = src_profileid
                attacker = dstip
                ip_identification = self.db.get_ip_identification(dstip)
                description = f"{rule} to destination address: {dstip} {ip_identification} port: {portproto} {port_info or ''}. Leaked location: {strings_matched}"

            elif self.db.has_profile(dst_profileid):
                attacker_direction = 'srcip'
                victim = dstip
                profileid = dst_profileid
                attacker = srcip
                ip_identification = self.db.get_ip_identification(srcip)
                description = f"{rule} to destination address: {srcip} {ip_identification} port: {portproto} {port_info or ''}. Leaked location: {strings_matched}"

            else:

                return


            twid = self.db.getTWofTime(profileid, ts)

            ts = utils.convert_format(ts, utils.alerts_format)
            if twid:
                twid = twid[0]
                source_target_tag = 'CC'

                evidence_type = 'NETWORK_gps_location_leaked'
                category = 'Malware'
                confidence = 0.9
                threat_level = 'high'
                self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence,
                                         description, ts, category, source_target_tag=source_target_tag, port=dport,
                                         proto=proto, profileid=profileid, twid=twid, uid=uid, victim=victim)

    def compile_and_save_rules(self):
        """
        Compile and save all yara rules in the compiled_yara_rules_path
        """

        try:
            os.mkdir(self.compiled_yara_rules_path)
        except FileExistsError:
            pass

        for yara_rule in os.listdir(self.yara_rules_path):
            compiled_rule_path = os.path.join(
                self.compiled_yara_rules_path, f'{yara_rule}_compiled'
            )

            if os.path.exists(compiled_rule_path):
                continue


            rule_path = os.path.join(self.yara_rules_path, yara_rule)

            cmd = f'yarac {rule_path} {compiled_rule_path} >/dev/null 2>&1'
            return_code = os.system(cmd)
            if return_code != 0:
                self.print(f"Error compiling {yara_rule}.")
                return False
        return True
    def delete_compiled_rules(self):
        """
        delete old YARA compiled rules when a new version of yara is being used
        """
        shutil.rmtree(self.compiled_yara_rules_path)
        os.mkdir(self.compiled_yara_rules_path)

    def find_matches(self):
        """Run yara rules on the given pcap and find matches"""
        for compiled_rule in os.listdir(self.compiled_yara_rules_path):
            compiled_rule_path = os.path.join(self.compiled_yara_rules_path, compiled_rule)



            cmd = f'yara -C {compiled_rule_path} "{self.pcap}" -p 7 -f -s '
            yara_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                shell=True
            )

            lines, error = yara_proc.communicate()
            lines = lines.decode()
            if error:
                if b'rules were compiled with a different version of YARA' in error.strip():
                    self.delete_compiled_rules()

                    self.run()
                else:
                    self.print (f"YARA error {yara_proc.returncode}: {error.strip()}")
                    return

            if not lines:

                return

            lines = lines.splitlines()
            matching_rule = lines[0].split()[0]

            for line in lines[1:]:

                line = line.split(':')

                offset = int(line[0], 16)

                var = line[1].replace('$', '')


                strings_matched = ' '.join(list(line[2:]))
                self.set_evidence_yara_match({
                    'rule': matching_rule,
                    'vars_matched': var,
                    'strings_matched': strings_matched,
                    'offset': offset,
                })

    def pre_main(self):
        utils.drop_root_privs()

        if not self.bin_found:
            return 1

        if self.compile_and_save_rules():

            self.find_matches()

    def main(self):
        return 1
