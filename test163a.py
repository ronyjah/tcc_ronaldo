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

class Test163a:

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
        self.__test_desc = self.__config.get('tests','1.6.3a')
        self.msg = self.__config.get('tests','1.6.3a')
        self.msg_lan = self.__config.get('tests','1.6.3a')
        self.addr_ceRouter = None        

    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t1.6.3','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t1.6.3','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t1.6.3','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t1.6.3','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t1.6.3','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t1.6.3','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t1.6.3','flag_prf'))

        self.__config_setup1_1.set_validlifetime(self.__config.get('t1.6.3','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t1.6.3','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t1.6.3','routerlifetime'))
        self.__config_setup1_1.set_intervalo(self.__config.get('t1.6.3','intervalo'))
        self.__config_setup1_1.set_pd_prefixlen(self.__config.get('t1.6.3','pd_prefixlen'))

        self.__config_setup1_1.set_prefix_addr(self.__config.get('setup1-1_advertise','ia_pd_address'))
        self.__config_setup1_1.set_dhcp_t1(self.__config.get('t1.6.3','dhcp_t1'))
        self.__config_setup1_1.set_dhcp_t2(self.__config.get('t1.6.3','dhcp_t2'))
        self.__config_setup1_1.set_dhcp_preflft(self.__config.get('t1.6.3','dhcp_preflft'))
        self.__config_setup1_1.set_dhcp_validlft(self.__config.get('t1.6.3','dhcp_validlft'))
        self.__config_setup1_1.set_dhcp_plen(self.__config.get('t1.6.3','dhcp_plen'))
    def get_addr_ceRouter(self):
        return self.addr_ceRouter
    
    def get_mac_ceRouter(self):
        return self.mac_ceRouter

    def set_status_lan(self,v):
        self.msg_lan = v

    def get_status_lan(self):
        return self.msg_lan


    def set_status(self,v):
        self.msg = v

    def get_status(self):
        return self.msg

    def run(self):
        @self.__app.route("/LAN",methods=['GET'])
        def envia_lan():

            return self.get_status_lan()

        @self.__app.route("/WAN",methods=['GET'])
        def enviawan():

            return self.get_status()
        self.__packet_sniffer_wan = PacketSniffer('test163a',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()
        self.set_flags()
        logging.info(self.__test_desc)
        t_test = 0

        time_over = False

        t_test1 = 0
        t_test2 = 0

        cache_wan = []
        while not self.__queue_wan.full():
            while self.__queue_wan.empty():
                if t_test < 120:
                    time.sleep(1)
                    t_test = t_test + 1
                    if t_test % 20 == 0:
                        logging.info('WAN: Tempo limite de teste 120 seg. Tempo atual: ' +str(t_test))
                        self.set_status('WAN: Tempo limite de teste 120 seg. Tempo atual:  ' +str(t_test))
                else:
                    self.__packet_sniffer_wan.stop() 
                    logging.info('Reprovado: Teste 1.6.3b- TImeout NAO RECEBEU DHCP SOLICIT')
                    self.set_status('Reprovado: Teste 1.6.3b TImeout NAO RECEBEU DHCP SOLICIT')
                    time.sleep(2)
                    self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    return False

            pkt = self.__queue_wan.get()
            cache_wan.append(pkt)
            wrpcap("wan-1.6.3a.cap",cache_wan)

            if not self.__config_setup1_1.get_setup1_1_OK():
                logging.info('WAN: Setup 1.1 em execução')
                self.set_status('WAN: Setup 1.1 em execução') 
                if not self.__config_setup1_1.get_disapproved():
                    self.__config_setup1_1.run_setup1_1(pkt)
                else:
                    logging.info('WAN: Reprovado Teste 1.6.3a - Falha em completar o setup 1.1')
                    self.set_status('Reprovado Teste 1.6.3a - Falha em completar o setup 1.1')
                    time.sleep(2)
                    self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    self.__packet_sniffer_wan.stop()
                    return False  
            
            if self.__config_setup1_1.get_ND_local_OK():
                if pkt.haslayer(DHCP6_Solicit):
                    self.__packet_sniffer_wan.stop()
                    logging.info('Aprovado Teste 1.6.3.a: Recebido Mensagem DHCPv6 Solicit')
                    self.set_status('Aprovado Teste 1.6.3.a: Recebido Mensagem DHCPv6 Solicit')
                    time.sleep(2)
                    self.set_status('APROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    return True
   
        self.__packet_sniffer_wan.stop()
        return True
     
        