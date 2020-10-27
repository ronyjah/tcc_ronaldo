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
from commontestsetup1_1 import CommonTestSetup1_1
from sendmsgs import SendMsgs
from configsetup1_1 import ConfigSetup1_1

format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")

class Test162b:

    def __init__(self,config,app):
        self.__app = app
        self.__queue_wan = Queue()
        self.__queue_lan = Queue()
        self.__config = config
        self.__interface = None
        self.__pkt = None
        self.__local_addr_ceRouter =None
        self.__sendmsgs = SendMsgs(self.__config)
        self.__config_setup1_1 = ConfigSetup1_1(self.__config)
        self.__wan_device_tr1 = self.__config.get('wan','device_wan_tr1')
        self.__wan_mac_tr1 = self.__config.get('wan','wan_mac_tr1')
        self.__link_local_addr = self.__config.get('wan','link_local_addr')
        self.__all_nodes_addr = self.__config.get('multicast','all_nodes_addr')
        self.__test_desc = self.__config.get('tests','1.6.2b')
        
    def send_echo_request_global(self):
        self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','global_wan_addr'))
        self.__config_setup1_1.set_ipv6_dst(self.__config.get('setup1-1_advertise','ia_na_address'))
        self.__config_setup1_1.set_ether_src(self.__config.get('wan','link_local_mac'))
        self.__config_setup1_1.set_ether_dst(self.get_ether_dst())
        self.__sendmsgs.send_echo_request(self.__config_setup1_1)

    def run(self):
        self.__packet_sniffer_wan = PacketSniffer('test162b',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__config_setup1_1.flags_partB()
        self.__packet_sniffer_wan.start()
        logging.info(self.__test_desc)
        t_test = 0
        time_over = False

        while not self.__queue_wan.full():
            while self.__queue_wan.empty():
                if t_test < 60:
                    time.sleep(1)
                    t_test = t_test + 1
                else:
                    time_over = True
            pkt = self.__queue_wan.get()
            if not self.__config_setup1_1.get_setup1_1_OK():
                if not self.__config_setup1_1.get_disapproved():
                    self.__config_setup1_1.run_setup1_1(pkt)
                else:
                    self.__packet_sniffer_wan.stop()
                    logging.info('Reprovado Teste 1.6.2.b - Falha em completar o Common Setup 1.1 da RFC')
                    return False
            
            else: 
                self.send_echo_request_global()
                if pkt.haslayer(ICMPv6EchoReply):
                    mac_dst = pkt[Ether].dst
                    if mac_dst == self.__config.get('wan','ra_mac'):
                        self.__packet_sniffer_wan.stop()
                        logging.info('Aprovado Teste 1.6.2.b: Recebido Mensagem Echo Reply com MAC do TN1 em MAC destino')
                        return True
                    else:
                        self.__packet_sniffer_wan.stop()
                        logging.info('Reprovado Teste 1.6.2.b: Recebido Mensagem Echo Reply Sem MAC do TN1 em MAC destino')
                        return False
        while not self.__queue_wan.empty():
            pkt = self.__queue_wan.get()       
        self.__packet_sniffer_wan.stop()
        return True
     
        