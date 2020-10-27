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

class Test274b:

    def __init__(self,config,app):
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
        self.__test_desc = self.__config.get('tests','2.7.4b')
        self.__t_lan = None
        self.__finish_wan = False
        self.__fail_test = None
        self.__config_setup_lan = ConfigSetup1_1_Lan(self.__config,self.__lan_device)



    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t1.6.6b','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t1.6.6b','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t1.6.6b','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t1.6.6b','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t1.6.6b','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t1.6.6b','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t1.6.6b','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t2.7.4b','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t2.7.4b','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.4b','routerlifetime'))
        self.__config_setup1_1.set_intervalo(self.__config.get('t1.6.6b','intervalo'))

        self.__config_setup1_1.set_dhcp_t1(self.__config.get('t2.7.4b','dhcp_t1'))
        self.__config_setup1_1.set_dhcp_t2(self.__config.get('t2.7.4b','dhcp_t2'))
        self.__config_setup1_1.set_dhcp_preflft(self.__config.get('t2.7.4b','dhcp_preflft'))
        self.__config_setup1_1.set_dhcp_validlft(self.__config.get('t2.7.4b','dhcp_validlft'))
        self.__config_setup1_1.set_dhcp_plen(self.__config.get('t2.7.4b','dhcp_plen'))
   
    def set_flags_lan(self):
        self.__config_setup_lan.set_elapsetime(self.__config.get('solicitlan','elapsetime'))
        self.__config_setup_lan.set_xid(self.__config.get('solicitlan','xid'))
        self.__config_setup_lan.set_fdqn(self.__config.get('solicitlan','clientfqdn'))
        self.__config_setup_lan.set_vendor_class(self.__config.get('solicitlan','vendorclass'))

        self.__config_setup_lan.set_enterprise(self.__config.get('solicitlan','enterpriseid'))
        self.__config_setup_lan.set_client_duid(self.__config.get('solicitlan','duid'))
        self.__config_setup_lan.set_iaid(self.__config.get('solicitlan','iaid'))

        
    def run_Lan(self):
        #self.__config_setup_lan_.flags_partA()
        logging.info('Thread da LAN inicio')
        t_test = 0
        sent_reconfigure = False
        time_over = False
        self.set_flags_lan()
        while not self.__queue_lan.full():
            while self.__queue_lan.empty():
                
                logging.info('Thread da LAN time')
                time.sleep(1)
                if self.__config_setup1_1.get_setup1_1_OK():
                    logging.info('Thread da WAN DONE')
#                    t_test = t_test + 1
 #                   if self.__config_setup1_1.get_recvd_dhcp_renew():
                #pkt = self.__queue_lan.get()
                    self.__config_setup_lan.set_setup_lan_start()
                    self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
                    self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                    self.__config_setup_lan.set_ether_dst(self.__config.get('multicast','all_mac_routers'))
                    self.__config_setup_lan.set_ipv6_dst(self.__config.get('multicast','all_routers_addr'))
                    self.__config_setup_lan.set_xid(self.__config.get('informationlan','xid'))
                    #self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
                    self.__config_setup_lan.set_elapsetime(self.__config.get('informationlan','elapsetime'))
                    self.__config_setup_lan.set_vendor_class(self.__config.get('informationlan','vendorclass'))
                    self.__sendmsgs.send_dhcp_information(self.__config_setup_lan)

                    time.sleep(1)
                    self.__config_setup_lan.set_setup_lan_start()
                    self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
                    self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                    self.__config_setup_lan.set_ether_dst(self.__config.get('multicast','all_mac_routers'))
                    self.__config_setup_lan.set_ipv6_dst(self.__config.get('general','all_routers_address'))
                    self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
                    self.__sendmsgs.send_icmp_rs(self.__config_setup_lan)
                    

            pkt = self.__queue_lan.get()
            if not self.__config_setup_lan.get_setup_OK():
                if not self.__config_setup_lan.get_disapproved():
                    self.__config_setup_lan.run_setup1_1(pkt)
                else:
                    logging.info('Reprovado Teste 2.7.4b - Falha em completar o Common Setup 1.1 da RFC')
                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True 
                    return False       
            else:
                logging.info('Setup LAN  Concluido')
                if self.__config_setup_lan.get_recvd_dhcp_srcladdr():
                    logging.info(' Teste 2.7.4b: DNS List Option OK.')
                    logging.info('Aprovado Teste2.7.4b.')
                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True
                    self.__fail_test = False 
                    return True                
                else:                     
                    logging.info(' Teste2.7.4b: Reprovado. Não foi recebido DNS List Option')
                    #logging.info(routerlifetime)
                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True 
                    self.__fail_test = True
                    return False


                
    def run(self):
        self.__t_lan =  Thread(target=self.run_Lan,name='LAN_Thread')
        self.__t_lan.start()
        
        self.__packet_sniffer_wan = PacketSniffer('Test273b-WAN',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()
        
        self.__packet_sniffer_lan = PacketSniffer('Test273b-LAN',self.__queue_lan,self,self.__config,self.__lan_device)
        test_lan = self.__packet_sniffer_lan.start()
        
        self.set_flags()
        logging.info(self.__test_desc)
        t_test = 0
        sent_reconfigure = False
        time_over = False
        #time.sleep(11111)
        finish_wan = True
        self.__config_setup1_1.set_pd_prefixlen(self.__config.get('t2.7.4b','pd_prefixlen')) 
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.4b','routerlifetime')) 
        #self.__config_setup1_1.active_DHCP_no_IA_PD()
        while not self.__queue_wan.full():
            while self.__queue_wan.empty():
                if t_test < 60:
                    time.sleep(1)
                    if t_test % 5 ==0:
                        self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
                        self.__config_setup1_1.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
                        self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','ra_address'))
                        self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
                        self.__sendmsgs.send_tr1_RA(self.__config_setup1_1)
                    t_test = t_test + 1
                else:
                    time_over = True
            pkt = self.__queue_wan.get()

            if not self.__config_setup1_1.get_setup1_1_OK():

                if not self.__config_setup1_1.get_disapproved():
                    self.__config_setup1_1.run_setup1_1(pkt)
                else:
                    logging.info('Reprovado Teste 2.7.3a - Falha em completar o Common Setup 1.1 da RFC')
                    self.__packet_sniffer_wan.stop() 
                    return False

            else:
                if not self.__finish_wan: 
                    print('WAN - Concluido')
                    print('LAN RESULT')
                    self.__config_setup1_1.check_layers(pkt)
                else:
                    self.__packet_sniffer_wan.stop()
                    if self.__fail_test:
                        return False
                    else:
                        return True

    
        self.__packet_sniffer_wan.stop()
        return False
     
        