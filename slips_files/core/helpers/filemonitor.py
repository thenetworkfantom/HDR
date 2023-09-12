import os
import json
import time
from watchdog.events import RegexMatchingEventHandler
from slips_files.common.imports import *


class FileEventHandler(RegexMatchingEventHandler):
    REGEX = [r'.*\.log$', r'.*\.conf$']

    def __init__(self, dir_to_monitor, input_type, db):
        super().__init__(self.REGEX)
        self.dir_to_monitor = dir_to_monitor
        utils.drop_root_privs()
        self.db = db
        self.input_type = input_type

    def on_created(self, event):
        filename, ext = os.path.splitext(event.src_path)
        if 'log' in ext:
            self.db.add_zeek_file(filename + ext)

    def on_moved(self, event):
        """this will be triggered everytime zeek renames all log files"""

        if event.dest_path != 'True':
            to_send = {'old_file': event.dest_path, 'new_file': event.src_path}
            to_send = json.dumps(to_send)
            self.db.publish('remove_old_files', to_send)

            time.sleep(1)

    def on_modified(self, event):
        """this will be triggered everytime zeek modifies a log file"""



        filename, ext = os.path.splitext(event.src_path)
        if 'reporter' in filename:


            for file in os.listdir(self.dir_to_monitor):
                if 'reporter' not in file:
                    continue
                with open(os.path.join(self.dir_to_monitor, file), 'r') as f:
                    while line := f.readline():
                        if 'termination' in line:

                            self.db.publish('control_channel', 'stop_slips')
                            break
        elif 'whitelist' in filename:
            self.db.publish('reload_whitelist', 'reload')
