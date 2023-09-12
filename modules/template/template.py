from slips_files.common.imports import *


class Template(Module, multiprocessing.Process):

    name = 'Template'
    description = 'Template module'
    authors = ['Template Author']

    def init(self):
        self.c1 = self.db.subscribe('new_ip')
        self.channels = {
            'new_ip': self.c1,
        }

    def pre_main(self):
        """
        Initializations that run only once before the main() function runs in a loop
        """
        utils.drop_root_privs()

    def main(self):
        """Main loop function"""
        if msg:= self.get_msg('new_ip'):
            data = len(self.db.getProfiles())
            self.print(f'Amount of profiles: {data}', 3, 0)

