import logging
import logging.config
import logging.handlers
from configparser import ConfigParser
from threading import Thread
from subprocess import call
import sys
import argparse
from scapy.all import *
from scapy.contrib.eigrp import *
from  scapy.contrib.ospf import *
from config import Config
import time
from packetsniffer import PacketSniffer
from commontestsetup1_1 import CommonTestSetup1_1
from sendmsgs import SendMsgs
from configsetup1_1 import ConfigSetup1_1

format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")

class Test167:

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
        self.__test_desc = self.__config.get('tests','1.6.7')
        self.__finish_wan = False
        self.__fail_test = False

    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t1.6.6b','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t1.6.6b','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t1.6.6b','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t1.6.6b','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t1.6.6b','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t1.6.6b','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t1.6.6b','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t1.6.6b','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t1.6.6b','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t1.6.6b','routerlifetime'))
        self.__config_setup1_1.set_intervalo(self.__config.get('t1.6.6b','intervalo'))    



    def run(self):
        self.__packet_sniffer_wan = PacketSniffer('test167',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()
        self.set_flags()
        logging.info(self.__test_desc)
        t_test = 0
        cache_wan = []
        sent_reconfigure = False
        time_over = False
        while not self.__queue_wan.full():
            while self.__queue_wan.empty():
                if t_test < 60:
                    time.sleep(1)
                    t_test = t_test + 1
                    logging.info('LAN: Tempo total de buscar por mensagens de roteamento dinamico Tempo 60 seg. Tempo atual ' +str(t_test))
                    self.set_status_lan('LAN: Tempo total de buscar por mensagens de roteamento dinamico Tempo 60 seg. Tempo atual ' +str(t_test)))
                else:
                    time_over = True
            pkt = self.__queue_wan.get()

            if not self.__config_setup1_1.get_setup1_1_OK():

                if not self.__config_setup1_1.get_disapproved():
                    self.__config_setup1_1.run_setup1_1(pkt)
                else:
                    logging.info('WAN: Reprovado Teste 1.6.7 - Falha em completar o setup LAN')
                    self.set_status('WAN: Reprovado Teste 1.6.7 - Falha em completar o setup LAN')
                    time.sleep(2)
                    self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    self.__packet_sniffer_wan.stop()
                    return False  
            else: 



                if pkt.haslayer(EIGRPv6ExtRoute):
                    logging.info(pkt.show())
                    logging.info('Reprovado Teste 1.6.7-EIGRPv6ExtRoute ')

                    self.set_status('WAN: Reprovado Teste 1.6.7-EIGRPv6ExtRoute')
                    time.sleep(2)
                    self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    self.__packet_sniffer_wan.stop()
                    return False  

                if pkt.haslayer(EIGRPExtRoute):
                    logging.info(pkt.show())
                    logging.info('Reprovado Teste 1.6.7-EIGRPExtRoute ')

                    self.set_status('WAN: Reprovado Teste 1.6.7-EIGRPExtRoute')
                    time.sleep(2)
                    self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    self.__packet_sniffer_wan.stop()
                    return False  

                if pkt.haslayer(EIGRPIntRoute):
                    logging.info(pkt.show())

                    logging.info('WAN: Reprovado Teste 1.6.7-EIGRPIntRoute')
                    self.set_status('WAN: Reprovado Teste 1.6.7-EIGRPIntRoute')
                    time.sleep(2)
                    self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    self.__packet_sniffer_wan.stop()
                    return False  

                if pkt.haslayer(EIGRPv6ExtRoute):
                    logging.info(pkt.show())
                    logging.info('WAN: Reprovado Teste 1.6.7-EIGRPv6ExtRoute')
                    self.set_status('WAN: Reprovado Teste 1.6.7-EIGRPv6ExtRoute')
                    time.sleep(2)
                    self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    self.__packet_sniffer_wan.stop()
                    return False  

                if pkt.haslayer(OSPF_Hdr):
                    logging.info(pkt.show())
                    logging.info('WAN: Reprovado Teste 1.6.7-OSPF_Hdr')
                    self.set_status('WAN: Reprovado Teste 1.6.7-OSPF_Hdr')
                    time.sleep(2)
                    self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    self.__packet_sniffer_wan.stop()
                    return False  

                if pkt.haslayer(OSPF_Hello):
                    logging.info(pkt.show())
                    logging.info('WAN: Reprovado Teste 1.6.7-OSPF_Hello')
                    self.set_status('WAN: Reprovado Teste 1.6.7-OSPF_Hello')
                    time.sleep(2)
                    self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    self.__packet_sniffer_wan.stop()
                    return False  
                if pkt.haslayer(OSPFv3_Hdr):
                    logging.info(pkt.show())
                    logging.info('WAN: Reprovado Teste 1.6.7-OSPFv3_Hdr')
                    self.set_status('WAN: Reprovado Teste 1.6.7-OSPFv3_Hdr')
                    time.sleep(2)
                    self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    self.__packet_sniffer_wan.stop()
                    return False  

                if pkt.haslayer(OSPFv3_Hello):
                    logging.info(pkt.show())
                    logging.info('WAN: Reprovado Teste 1.6.7-OSPFv3_Hello')
                    self.set_status('WAN: Reprovado Teste 1.6.7-OSPFv3_Hello')
                    time.sleep(2)
                    self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    self.__packet_sniffer_wan.stop()
                    return False  
                if pkt.haslayer(OSPFv3_Router_LSA):
                    logging.info(pkt.show())
                     logging.info('WAN: Reprovado Teste 1.6.7-OSPFv3_Router_LSA')
                    self.set_status('WAN: Reprovado Teste 1.6.7-OSPFv3_Router_LSA')
                    time.sleep(2)
                    self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    self.__packet_sniffer_wan.stop()
                    return False  

                elif time_over :
                    self.__packet_sniffer_wan.stop() 
                    logging.info('Aprovado: Teste 1.6.7-Nao houveram mensagem de roteamento dinâmico durante o período de teste')
                    self.set_status_lan('Aprovado: Teste 1.6.7-Nao houveram mensagem de roteamento dinâmico durante o período de teste')
                    time.sleep(2)
                    self.set_status_lan('APROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    
                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True
                    self.__fail_test = False 
                    return True        

     
        self.__packet_sniffer_wan.stop()
        return False
     
        