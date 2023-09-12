from style import green

import subprocess
import os
import threading
from multiprocessing import Queue

class UIManager:
    def __init__(self, main):
        self.main = main

    def check_if_webinterface_started(self):
        if not hasattr(self, 'webinterface_return_value'):
            return

        if self.webinterface_return_value.empty():

            delattr(self, 'webinterface_return_value')
            return
        if self.webinterface_return_value.get() != True:

            delattr(self, 'webinterface_return_value')
            return

        self.main.print(f"Slips {green('web interface')} running on "
                   f"http://localhost:55000/")
        delattr(self, 'webinterface_return_value')

    def start_webinterface(self):
        """
        Starts the web interface shell script if -w is given
        """
        def detach_child():
            """
            Detach the web interface from the parent process group(slips.py), the child(web interface)
             will no longer receive signals and should be manually killed in shutdown_gracefully()
            """
            os.setpgrp()

        def run_webinterface():
            command = ['python3', 'webinterface/app.py']
            webinterface = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                preexec_fn=detach_child
            )

            self.main.db.store_process_PID('Web Interface', webinterface.pid)
            self.webinterface_return_value.put(True)
            error = webinterface.communicate()[1]
            if error:
                self.webinterface_return_value.get()
                self.webinterface_return_value.put(False)
                pid = self.main.metadata_man.get_pid_using_port(55000)
                self.main.print (f"Web interface error:\n"
                            f"{error.strip().decode()}\n"
                            f"Port 55000 is used by PID {pid}")

        self.webinterface_return_value = Queue()
        self.webinterface_thread = threading.Thread(
            target=run_webinterface,
            daemon=True,
        )
        self.webinterface_thread.start()


