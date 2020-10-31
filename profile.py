""" Profile Module """

from pathlib import Path
import os
import sys
import logging
import time
import json
import glob

STATISTICS_SIZE = 100

format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")
                    
class Profile:

    def __init__(self,name,config):
        self.__name = name
        self.__steps_list = []
        self.test_counter = -1


    def wait_lan_connect(self, lan_interface):
        self.add_step(WaitLanConnect(lan_interface))


    def get_name(self):
        return self.__name

    def add_step(self, step):
        self.__steps_list.append(step)

    def steps_number(self):
        return len(self.__steps_list)


    def get_config(self):
        return self.profile_conf

    def execute(self, profile_name,profile):
        logging.debug('Profile - executing profile ' + self.__name)

        _profile = profile
        stepsNumber = len(self.__steps_list)
        stepsCounter = -1

        for step in self.__steps_list:

  
            progress = int(round((stepsCounter/stepsNumber) * 100))

 
            stepsCounter += 1

            
            test_ok = step.run()
            if not test_ok:
                logging.info('TESTE CONCLUIDO COM FALHA')
                _profile.unlock_test()
                _profile.activate()
                

            logging.info('TESTE CONCLUIDO COM SUCESSO')
            _profile.unlock_test()
            _profile.activate()
            

    def configure_interfaces(self):
        device = self.__config.get('jiga', 'lan_device')
        ip = '10.0.0.2'

        try:
            ip = self.__config.get('jiga', 'local_ip')
        except:
            logging.info('Profile: using default ip to setup interface: 10.0.0.2')


    def activate(self):
        """ Needs to be implemented by derived class """
        pass
