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
import pdb
format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")

class Test164a:

    def __init__(self,config):
        self.__queue_wan = Queue()
        self.__queue_lan = Queue()
        self.__config = config
        self.__interface = None
        self.__pkt = None
        self.addr_ceRouter = None
        self.mac_ceRouter = None
        self.__local_addr_ceRouter =None
        self.__ND_local_OK = False
        self.__sendmsgs = SendMsgs(self.__config)
        self.__config_setup1_1 = ConfigSetup1_1(self.__config)
        self.__wan_device_tr1 = self.__config.get('wan','device_wan_tr1')
        self.__wan_mac_tr1 = self.__config.get('wan','wan_mac_tr1')
        self.__link_local_addr = self.__config.get('wan','link_local_addr')
        self.__all_nodes_addr = self.__config.get('multicast','all_nodes_addr')
        self.__test_desc = self.__config.get('tests','1.6.4')
        

    def get_addr_ceRouter(self):
        return self.addr_ceRouter
    
    def get_mac_ceRouter(self):
        return self.mac_ceRouter

    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t1.6.4','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t1.6.4','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t1.6.4','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t1.6.4','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t1.6.4','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t1.6.4','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t1.6.4','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t1.6.4','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t1.6.4','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t1.6.4','routerlifetime'))
        self.__config_setup1_1.set_intervalo(self.__config.get('t1.6.4','intervalo'))    

    def run(self):
        self.__packet_sniffer_wan = PacketSniffer('test164',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()

        self.set_flags()         
        logging.info(self.__test_desc)
        t_test = 0
        sent_reconfigure = False
        time_over = False
        rs_ok = False
        send_ra = False
        send_ns =False
        send_ra2 = False
        send_ra_M_1 =False
        while not self.__queue_wan.full():
            while self.__queue_wan.empty():
                if t_test < 60:
                    time.sleep(1)
                    t_test = t_test + 1
                else:
                    time_over = True
            pkt = self.__queue_wan.get()
            #if not self.__ND_local_OK:

            if pkt.haslayer(ICMPv6ND_NS):

                if pkt[ICMPv6ND_NS].tgt == '::':

                    pass
                if pkt[IPv6].src == self.__config.get('wan','link_local_addr'):
                    pass
                if pkt[IPv6].src == self.__config.get('wan','global_wan_addr'):
                    pass
                if pkt[IPv6].src == '::':
                    if pkt[ICMPv6ND_NS].tgt != '::':

                        self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)

                        self.__config_setup1_1.set_local_addr_ceRouter(pkt[ICMPv6ND_NS].tgt)

                        self.__ND_local_OK = True

                    if pkt[ICMPv6ND_NS].tgt != '::' and pkt[IPv6].src != '::':

                        pkt.show()

                    # self.addr_ceRouter = pkt[ICMPv6ND_NS].tgt
                    #     self.mac_ceRouter = pkt[Ether].src
                    #     self.__ND_local_OK = True

            if pkt.haslayer(ICMPv6ND_RS) and not self.__ND_local_OK:
                return False
            else:
                if not send_ns:
                    #self.__sendmsgs.set_flags_common_setup(self.__config_setup1_1)
                    self.__config_setup1_1.set_ether_src(self.__config.get('wan','link_local_mac'))
                    self.__config_setup1_1.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
                    self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','global_wan_addr'))
                    self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
                    self.__config_setup1_1.set_tgt(self.__config.get('wan','link_local_addr'))
                    
                    self.__sendmsgs.send_icmp_ns(self.__config_setup1_1)
                    send_ns = True
                    continue
            if pkt.haslayer(DHCP6_Solicit) and send_ns and not send_ra_M_1 :       
                if not send_ra_M_1:
                    self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
                    self.__config_setup1_1.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
                    self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','link_local_addr'))
                    self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
                    self.__sendmsgs.send_tr1_RA(self.__config_setup1_1)
                    send_ra = True
                    send_ra_M_1 = True
                    continue

                    #self.set_ether_dst(pkt[Ether].src)

            if send_ra_M_1 and not send_ra2:
                if pkt.haslayer(DHCP6_Solicit):
                    



                        self.__config_setup1_1.set_flag_M("0")
                        self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
                        self.__config_setup1_1.set_ether_dst(self.__config_setup1_1.get_mac_ceRouter())
                        self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','link_local_addr'))
                        self.__config_setup1_1.set_ipv6_dst(self.__config_setup1_1.get_local_addr_ceRouter())
                        self.__sendmsgs.send_tr1_RA(self.__config_setup1_1)
                        send_ra2 = True
                        continue
            if send_ra2:
                if pkt.haslayer(DHCP6_Solicit):
                    if pkt.haslayer(DHCP6OptIA_NA):
                        return True
            #if pkt.haslayer(DHCP6_Solicit) and send_ra2: 

                # print('local addr')
                    # print(self.get_local_addr_ceRouter())
                    # print('ether dst')
                    # print(self.get_ether_dst())
                    #self.__ND_local_OK = True
           # if not self.__config_setup1_1.get_setup1_1_OK():

             #   if not self.__config_setup1_1.get_disapproved():
             #       self.__config_setup1_1.run_setup1_1(pkt)
            #    else:
             #       logging.info('Reprovado Teste 1.6.3.c - Falha em completar o Common Setup 1.1 da RFC')
            #        self.__packet_sniffer_wan.stop() 
             #       return False

            #else: 
            #    self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','link_local_addr'))
             #   self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','dhcp_relay_agents_and_servers_addr'))
             #   self.__config_setup1_1.set_ether_src(self.__config.get('wan','link_local_mac'))
             #   self.__config_setup1_1.set_ether_dst(self.__config_setup1_1.get_ether_dst())
              #  self.__config_setup1_1.set_dhcp_reconf_type(self.__config.get('t1.6.3','msg_type'))

                # if pkt.haslayer(DHCP6_Renew):
                #     logging.info('Reprovado Teste 1.6.3.c - Respondeu ao DHCP6 reconfigure incompleto')
                #     logging.info(pkt.show())
                #     self.__packet_sniffer_wan.stop()
                #     return False
                # elif time_over :
                #     if not sent_reconfigure:
                #         self.__packet_sniffer_wan.stop()
                #         logging.info('Falha: Teste 1.6.3.c. Tempo finalizado mas Não Enviou DHCP Reconfigure')

                #         return False
                #     else:
                #         self.__packet_sniffer_wan.stop() 
                #         logging.info('Aprovado: Teste 1.6.3.c. Tempo finalizado e não recebeu DHCP Renew em DHCP Reconf adulterado')

                #         return True
                # if not sent_reconfigure:
                #     self.__sendmsgs.send_dhcp_reconfigure_no_auth(self.__config_setup1_1)
                #     sent_reconfigure = True
            

                # if pkt.haslayer(DHCP6_Solicit):
                #     self.__packet_sniffer_wan.stop()
                #     while not self.__queue_wan.empty():
                #         pkt = self.__queue_wan.get() 
                #     return True
        # while not pkt.haslayer(IPv6):
        #     pkt = self.__queue_wan.get()      
        self.__packet_sniffer_wan.stop()
        return False
     
        