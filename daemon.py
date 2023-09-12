from slips_files.common.imports import *
import sys
import os
from signal import SIGTERM

class Daemon():
    description = 'This module runs when slips is in daemonized mode'

    def __init__(self, slips):
        self.slips = slips
        self.slips.set_mode('daemonized', daemon=self)
        self.pidfile_dir = '/var/lock'
        self.pidfile = os.path.join(self.pidfile_dir, 'slips_daemon.lock')
        self.read_configuration()
        if not self.slips.args.stopdaemon:
            self.prepare_output_dir()

        try:
            with open(self.pidfile, 'r') as pidfile:
                self.pid = int(pidfile.read().strip())
        except (IOError, FileNotFoundError):
            self.pid = None


    def print(self, text):
        """Prints output to logsfile specified in slips.conf"""
        with open(self.logsfile, 'a') as f:
            f.write(f'{text}\n')

    def create_std_streams(self):
        """Create standard steam files and dirs and clear them"""

        std_streams = [self.stderr, self.stdout, self.logsfile]
        for file in std_streams:
            if '-S' in sys.argv and file != self.stderr:
                continue
            try:
                open(file, 'w').close()
            except (FileNotFoundError, NotADirectoryError):
                os.mkdir(os.path.dirname(file))
                open(file, 'w').close()

    def prepare_std_streams(self, output_dir):
        """
        prepare the path of stderr, stdout, logsfile
        """

        self.stderr = os.path.join(output_dir, self.stderr)
        self.stdout = os.path.join(output_dir, self.stdout)
        self.logsfile = os.path.join(output_dir, self.logsfile)

    def read_configuration(self):
        conf = ConfigParser()
        self.logsfile = conf.logsfile()
        self.stdout = conf.stdout()
        self.stderr = conf.stderr()

        self.stdin = '/dev/null'

    def prepare_output_dir(self):
        if '-o' in sys.argv:
            self.prepare_std_streams(self.slips.args.output)
        else:
            try:
                output_dir = '/var/log/slips/'
                try:
                    os.mkdir(output_dir)
                except FileExistsError:
                    pass

                tmpfile = os.path.join(output_dir, 'tmp')
                open(tmpfile, 'w').close()
                os.remove(tmpfile)
                self.prepare_std_streams(output_dir)
                self.slips.args.output = output_dir
            except PermissionError:
                self.prepare_std_streams(self.slips.args.output)

        self.create_std_streams()


        if '-S' not in sys.argv:
            self.print(
                f'Logsfile: {self.logsfile}\n'
                f'pidfile: {self.pidfile}\n'
                f'stdin : {self.stdin}\n'
                f'stdout: {self.stdout}\n'
                f'stderr: {self.stderr}\n'
            )

            self.print('Done reading configuration and setting up files.\n')

    def delete_pidfile(self):
        """Deletes the pidfile to mark the daemon as closed"""
        if os.path.exists(self.pidfile):
            os.remove(self.pidfile)
            self.print('pidfile deleted.')
        else:
            self.print(f"Can't delete pidfile, {self.pidfile} doesn't exist.")

            self.print('Either Daemon stopped normally or an error occurred.')

    def daemonize(self):
        """
        Does the Unix double-fork to create a daemon
        """
        try:
            self.pid = os.fork()
            if self.pid > 0:

                sys.exit(0)
        except OSError as e:
            sys.stderr.write(f'Fork #1 failed: {e.errno} {e.strerror}\n')
            self.print(f'Fork #1 failed: {e.errno} {e.strerror}\n')
            sys.exit(1)

        os.setsid()
        os.umask(0)
        try:
            self.pid = os.fork()
            if self.pid > 0:
                sys.exit(0)
        except OSError as e:
            sys.stderr.write(f'Fork #2 failed: {e.errno} {e.strerror}\n')
            self.print(f'Fork #2 failed: {e.errno} {e.strerror}\n')
            sys.exit(1)
        sys.stdout.flush()
        sys.stderr.flush()


        with open(self.stdin, 'r') as stdin, open(
            self.stdout, 'a+'
        ) as stdout, open(self.stderr, 'a+') as stderr:
            os.dup2(stdin.fileno(), sys.stdin.fileno())
            os.dup2(stdout.fileno(), sys.stdout.fileno())
            os.dup2(stderr.fileno(), sys.stderr.fileno())

        if not os.path.exists(self.pidfile_dir):
            os.mkdir(self.pidfile_dir)
        self.pid = str(os.getpid())
        with open(self.pidfile, 'w+') as pidfile:
            pidfile.write(self.pid)
    def start(self):
        """Main function, Starts the daemon and starts slips normally."""
        self.print('Daemon starting...')
        self.daemonize()
        self.print(f'Slips Daemon is running. [PID {self.pid}]\n')
        self.slips.start()

    def get_last_opened_daemon_info(self):
        """
        get information about the last opened slips daemon from running_slips_info.txt
        """
        try:
            with open(self.slips.redis_man.running_logfile, 'r') as f:
                for line in f.read().splitlines()[::-1]:
                    if (
                        line.startswith('#')
                        or line.startswith('Date')
                        or len(line) < 3
                    ):
                        continue
                    line = line.split(',')
                    is_daemon = bool(line[7])
                    if not is_daemon:
                        continue
                    port, output_dir, slips_pid  = line[2], line[5], line[6]
                    return (port, output_dir, slips_pid)
        except FileNotFoundError:
            self.print(f"Warning: {self.slips.redis_man.running_logfile} is not found. Can't get daemon info."
                       f" Slips won't be completely killed.")
            return False

    def killdaemon(self):
        """ Kill the damon process only (aka slips.py) """
        try:
            os.kill(int(self.pid), SIGTERM)
        except ProcessLookupError:
            pass

    def stop(self):
        """Stop the daemon"""

        self.delete_pidfile()
        self.killdaemon()
        info = self.get_last_opened_daemon_info()
        if not info:
            return
        port, output_dir, self.pid = info
        self.stderr = 'errors.log'
        self.stdout = 'slips.log'
        self.logsfile = 'slips.log'
        self.prepare_std_streams(output_dir)
        db = DBManager(output_dir,
                       multiprocessing.Queue(),
                       port,
                       start_sqlite=False,
                       flush_db=False)
        db.set_slips_mode('daemonized')
        self.slips.set_mode('daemonized', daemon=self)

        self.slips.input_information = db.get_input_file()
        self.slips.db = db

        self.slips.proc_man.slips_logfile = self.logsfile
        self.slips.proc_man.shutdown_gracefully()
