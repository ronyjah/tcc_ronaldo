import logging
import logging.config
import logging.handlers
from configparser import ConfigParser
from threading import Thread
from subprocess import call
import sys
import argparse
from scapy.all import *
from config import Config
import time
from packetsniffer import PacketSniffer
from test161 import Test161
from engine import Engine

format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")
def read_config():
    lan_device = config.get('lan','lan_device')
    return lan_device

class RfcLan():
    def __init__(self,configdir):
        self.load_configuration(configdir)
        self.__view = None
        self.__engine = Engine()
        self.__lan_device = self.__config.get('lan','lan_device')
        self.__src_rs_address = self.__config.get('lan', 'source_rs')
        self.__mac_address = self.__config.get('lan', 'mac_address')
        self.__aprovado = None

        
    def load_configuration(self, conf_dir):
        configfile = conf_dir + '/rfclan.conf'
        configparser = ConfigParser()
        configparser.read(configfile)
        logging.info("Configuration loaded")
        
        self.__config = Config(configparser, configfile)
        self.__config.set('directories', 'conf_dir', conf_dir)

    def main(self):
        try:

            self.__engine.load_profiles(self.__config) # cria objetos dos equipamentos de teste
            profile_name = self.__config.get('rfc', 'profile') # seleciona o equipamento
            self.__engine.set_profile(profile_name) # função active dentro da classe do EUT. addsteps
            self.__engine.start() # funcão execute
            #self.commonTestSetup11()
            # 
            #self.TestceRouter271cLAN()
            
            while 1:
                pass
            #print(self.__lan_device)
        
        except KeyboardInterrupt:
            logging.info('This is the end.')
            sys.exit(0)
            
        except BaseException as error:
            logging.error(error)
            logging.info('Ooops... Aborting!')



def init_RfcLan(configdir):
    rfclan = RfcLan(configdir)
    rfclan.main()

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--configdir', help='the config directory',type=str)
    args = parser.parse_args()
    if not args.configdir:
        parser.print_help()
        sys.exit(0)
        
    init_RfcLan(args.configdir)

if __name__ == "__main__":
	main()


    