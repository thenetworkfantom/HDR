import os
import platform
import psutil
import pwd



class Notify:
    def __init__(self):
        self.bin_found = False
        if self.is_notify_send_installed():
            self.bin_found = True


    def is_notify_send_installed(self) -> bool:
        """
        Checks if notify-send bin is installed
        """
        cmd = 'notify-send > /dev/null 2>&1'
        returncode = os.system(cmd)
        if returncode == 256:

            return True

        print("notify-send is not installed. install it using:\nsudo apt-get install libnotify-bin")
        return False


    def setup_notifications(self):
        """
        Get the used display, the user using this display and the uid of this user in case of using Slips as root on linux
        """

        if (platform.system() != 'Linux'
                or os.geteuid() != 0):
            self.notify_cmd = 'notify-send -t 5000 '
            return False
        used_display = psutil.Process().environ()['DISPLAY']
        command = f'who | grep "({used_display})" '
        cmd_output = os.popen(command).read()


        if len(cmd_output) < 5:
            user = str(psutil.users()[0].name)
        else:
            user = cmd_output.split('\n')[0].split()[0]
        uid = pwd.getpwnam(user).pw_uid
        self.notify_cmd = f'sudo -u {user} DISPLAY={used_display} ' \
                          f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus notify-send -t 5000 '

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
