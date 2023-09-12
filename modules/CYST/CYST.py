from slips_files.common.abstracts import Module
import multiprocessing
import socket
import json
import os
import errno
import sys
from pprint import pp
import contextlib

class Module(Module, multiprocessing.Process):

    name = 'CYST'
    description = 'Communicates with CYST simulation framework'
    authors = ['Alya Gomaa']

    def init(self):
        self.port = None
        self.c1 = self.db.subscribe('new_alert')
        self.channels = {'new_alert': self.c1}
        self.cyst_UDS = '/run/slips.sock'
        self.conn_closed = False

    def initialize_unix_socket(self):
        """
        If the socket is there, slips will connect to itm if not, slips will create it
        """
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if os.path.exists(self.cyst_UDS):
            os.unlink(self.cyst_UDS)

        sock.bind(self.cyst_UDS)
        failure = sock.listen(2)
        if not failure:
            self.print(f"Slips is now listening. waiting for CYST to connect.")
        else:
            error = (f"Failed to initialize sips socket. Error code: {failure}")
            return False, error

        connection, client_address = sock.accept()
        return sock, connection


    def get_flow(self):
        """
        reads 1 flow from the CYST socket and converts it to dict
        returns a dict if the flow was received or False if there was an error
        """
        try:
            self.cyst_conn.settimeout(5)

            flow_len = self.cyst_conn.recv(5).decode()
            try:
                flow_len: int = int(flow_len)
            except ValueError:
                self.print(f"Received invalid flow length from cyst: {flow_len}")
                self.conn_closed = True
                return False

            flow: bytes = self.cyst_conn.recv(flow_len).decode()

        except socket.timeout:
            self.print("timeout but still listening for flows.")
            return False
        except socket.error as e:
            err = e.args[0]
            if err == errno.EAGAIN or err == errno.EWOULDBLOCK:

                return False
            else:
                self.print(f"An error occurred: {e}")
                self.conn_closed = True
                return False



        if not flow:
            self.print(f"CYST closed the connection.")
            self.conn_closed = True
            return False
        try:
            flow = json.loads(flow)
            return flow
        except json.decoder.JSONDecodeError:
            self.print(f'Invalid json line received from CYST. {flow}', 0, 1)
            return False

    def send_length(self, msg: bytes):
        """
        takes care of sending the msg length with padding before the actual msg
        """



        msg_len = str(len(msg)).encode()

        msg_len += (5- len(msg_len) ) *b' '

        self.cyst_conn.sendall(msg_len)

    def send_alert(self, alert_ID: str, ip_to_block: str):
        """
        Sends the alert ID and the IDs of the evidence causing this alert to cyst
        """
        alert_to_send = {
            'slips_msg_type': 'alert',
            'alert_ID': alert_ID,
            'ip_to_block': ip_to_block
        }

        self.print(f"Sending alert to CYST: ")
        self.print(pp(alert_to_send))


        alert_to_send: bytes = json.dumps(alert_to_send).encode()
        self.send_length(alert_to_send)

        try:
            self.cyst_conn.sendall(alert_to_send)
        except BrokenPipeError:
            self.conn_closed = True
            return

    def close_connection(self):
        print(f"Closing connection", 0, 1)
        if hasattr(self, 'sock'):
            self.sock.close()

        os.unlink(self.cyst_UDS)


    def is_cyst_enabled(self):

        custom_flows = '-im' in sys.argv or '--input-module' in sys.argv
        if not custom_flows:
            return False

        with contextlib.suppress(ValueError):

            if self.name in sys.argv[sys.argv.index('--input-module') + 1]:
                return True

            if self.name in sys.argv[sys.argv.index('--im') + 1]:
                return True

        return True

    def shutdown_gracefully(self):
        self.close_connection()


        self.db.publish('control_channel', 'stop_slips')
        return

    def pre_main(self):

        if not self.db.is_cyst_enabled():
            return 1
        self.db.set_cyst_enabled()

        self.print(f"Initializing socket", 0, 1)
        self.sock, self.cyst_conn = self.initialize_unix_socket()
        if not self.sock:
            return 1
        self.print(f"Done initializing socket", 0, 1)

    def main(self):
        """
        returning non-zero will cause shutdown_gracefully to be called
        """

        if self.conn_closed :
            self.print('Connection closed by CYST.', 0, 1)
            return 1


        if flow := self.get_flow():

            to_send = {
                'flow': flow,
                'module': self.name
                }

            self.print(f"Received flow from cyst")
            self.print(pp(to_send))

            self.db.publish('new_module_flow', json.dumps(to_send))


        if self.conn_closed:
            self.print('Connection closed by CYST.', 0, 1)
            return 1

        if msg := self.get_msg('new_alert'):
            self.print(f"Cyst module received a new blocking request . sending to CYST ... ")
            alert_info: dict = json.loads(msg['data'])
            profileid = alert_info['profileid']


            alert_ID = alert_info['alert_ID']
            self.send_alert(alert_ID, profileid.split('_')[-1])



