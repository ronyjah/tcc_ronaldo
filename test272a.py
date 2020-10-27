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
from configsetup1_1_lan import ConfigSetup1_1_Lan
format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")

class Test272a:

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
        #self.__config_setup_lan = ConfigSetup1_1_Lan(self.__config)
        self.__wan_device_tr1 = self.__config.get('wan','device_wan_tr1')
        self.__lan_device = self.__config.get('lan','lan_device')
        self.__wan_mac_tr1 = self.__config.get('wan','wan_mac_tr1')
        self.__link_local_addr = self.__config.get('wan','link_local_addr')
        self.__all_nodes_addr = self.__config.get('multicast','all_nodes_addr')
        self.__test_desc = self.__config.get('tests','2.7.2a')
        self.__t_lan = None
        self.msg = self.__config.get('tests','2.7.2a')
        self.msg_lan =self.__config.get('tests','2.7.2a')
        self.__config_setup_lan = ConfigSetup1_1_Lan(self.__config,self.__lan_device)



    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t1.6.6b','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t1.6.6b','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t1.6.6b','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t1.6.6b','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t1.6.6b','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t1.6.6b','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t1.6.6b','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t2.7.2b','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t2.7.2b','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.2b','routerlifetime'))
        self.__config_setup1_1.set_intervalo(self.__config.get('t1.6.6b','intervalo'))   

        self.__config_setup1_1.set_dhcp_t1(self.__config.get('t2.7.2b','dhcp_t1'))
        self.__config_setup1_1.set_dhcp_t2(self.__config.get('t2.7.2b','dhcp_t2'))
        self.__config_setup1_1.set_dhcp_preflft(self.__config.get('t2.7.2b','dhcp_preflft'))
        self.__config_setup1_1.set_dhcp_validlft(self.__config.get('t2.7.2b','dhcp_validlft'))
        self.__config_setup1_1.set_dhcp_plen(self.__config.get('t2.7.2b','dhcp_plen'))

        


    def set_flags_lan(self):
        self.__config_setup_lan.set_elapsetime(self.__config.get('solicitlan','elapsetime'))
        self.__config_setup_lan.set_xid(self.__config.get('solicitlan','xid'))
        self.__config_setup_lan.set_fdqn(self.__config.get('solicitlan','clientfqdn'))
        self.__config_setup_lan.set_vendor_class(self.__config.get('solicitlan','vendorclass'))
        #self.__config_setup_lan.set_t1(self.__config.get('solicitlan','elapsetime'))
        #self.__config_setup_lan.set_t2(self.__config.get('solicitlan','elapsetime'))
        self.__config_setup_lan.set_enterprise(self.__config.get('solicitlan','enterpriseid'))
        self.__config_setup_lan.set_client_duid(self.__config.get('solicitlan','duid'))
        self.__config_setup_lan.set_iaid(self.__config.get('solicitlan','iaid'))


    def set_status_lan(self,v):
        self.msg_lan = v

    def get_status_lan(self):
        return self.msg_lan


    def set_status(self,v):
        self.msg = v

    def get_status(self):
        return self.msg



    def run_Lan(self):
        @self.__app.route("/LAN",methods=['GET'])
        def envia_lan():
            return self.get_status_lan()
        #self.__config_setup_lan_.flags_partA()
        logging.info('Thread da LAN')
        t_test = 0
        sent_reconfigure = False
        time_over = False
        self.set_flags_lan()
        cache_lan = []
        while not self.__queue_lan.full():
            while self.__queue_lan.empty():
                if t_test < 60:
                    time.sleep(1)
                    t_test = t_test + 1
                else:
                    time_over = True
            pkt = self.__queue_lan.get()
            cache_lan.append(pkt)
            wrpcap("lan-2.7.2a.cap",cache_lan)
            if not self.__config_setup_lan.get_setup_OK():
                if not self.__config_setup_lan.get_disapproved():
                    self.__config_setup_lan.run_setup1_1(pkt)
                else:
                    logging.info('Reprovado Teste 2.7.1b - Falha em completar o Common Setup 1.1 da RFC')
                    self.__packet_sniffer_lan.stop() 
                    return False       
            else:
                logging.info('Setup LAN  Concluido')
                #self.__packet_sniffer_wan.stop() 
                r_plen_CeRouter = self.__config_setup_lan.get_r_plen_CeRouter()
                r_rtlifetime_CeRouter = self.__config_setup_lan.get_r_lifetime_CeRouter()
                #validlifetime = self.__config_setup_lan.get_validlifetime_CeRouter()
                if r_plen_CeRouter == int(self.__config.get('t2.7.2a','pd_prefixlen')):
                    logging.info('Aprovado Teste 2.7.2a r_plen_CeRouter é igual pd_prefixlen')
                    #self.__packet_sniffer_lan.stop()
                    #return True
                else:                     
                    logging.info('Reprovado -r_plen_CeRouter nao é igual pd_prefixlen')
                    logging.info(r_plen_CeRouter)
                    self.__packet_sniffer_lan.stop()
                    return False

                if r_rtlifetime_CeRouter < int(self.__config.get('t2.7.2a','routerlifetime')):
                    logging.info(' Teste 2.7.2a: r_rtlifetime_CeRouter OK. r_rtlifetime dentro do especificado no RA')
                    #self.__packet_sniffer_lan.stop()
                    #return True
                else:                     
                    logging.info(' Teste2.7.2a: Reprovado. preferredlifetime acima do especificado no RA')
                    logging.info(r_rtlifetime_CeRouter)
                    self.__packet_sniffer_lan.stop()
                    return False

                logging.info('Aprovado Teste2.7.2a.')
                self.__packet_sniffer_lan.stop()
                return True
                


  


    def run(self):
        @self.__app.route("/WAN",methods=['GET'])
        def enviawan():
            return self.get_status()
        self.__t_lan =  Thread(target=self.run_Lan,name='LAN_Thread')
        self.__t_lan.start()
        
        self.__packet_sniffer_wan = PacketSniffer('Test271b-WAN',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()
        
        self.__packet_sniffer_lan = PacketSniffer('Test271b-LAN',self.__queue_lan,self,self.__config,self.__lan_device)
        test_lan = self.__packet_sniffer_lan.start()
        cache_wan = []
        self.set_flags()
        logging.info(self.__test_desc)
        t_test = 0
        sent_reconfigure = False
        time_over = False
        #time.sleep(11111)
        finish_wan = True
        self.__config_setup1_1.set_pd_prefixlen(self.__config.get('t2.7.2a','pd_prefixlen')) 
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.2a','routerlifetime')) 
        while not self.__queue_wan.full():
            while self.__queue_wan.empty():
                if t_test < 60:
                    time.sleep(1)
                    t_test = t_test + 1
                else:
                    time_over = True
            pkt = self.__queue_wan.get()
            cache_wan.append(pkt)
            wrpcap("WAN-2.7.2a.cap",cache_wan)
            if not self.__config_setup1_1.get_setup1_1_OK():

                if not self.__config_setup1_1.get_disapproved():
                    self.__config_setup1_1.run_setup1_1(pkt)
                else:
                    logging.info('Reprovado Teste 2.7.1b - Falha em completar o Common Setup 1.1 da RFC')
                    self.__packet_sniffer_wan.stop() 
                    return False

            else: 
                if not finish_wan:
                    self.__packet_sniffer_wan.stop()
                    finish_wan = True 
      
        self.__packet_sniffer_wan.stop()
        return False
     
        