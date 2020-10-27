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

class Test323b:

    def __init__(self,config,app):
        self.__queue_wan = Queue()
        self.__queue_lan = Queue()
        self.__config = config
        self.__interface = None
        self.__pkt = None
        self.__local_addr_ceRouter =None
        self.__sendmsgs = SendMsgs(self.__config)
        self.__config_setup1_1 = ConfigSetup1_1(self.__config)
        self.__wan_device_tr1 = self.__config.get('wan','device_wan_tr1')
        self.__lan_device = self.__config.get('lan','lan_device')
        self.__wan_mac_tr1 = self.__config.get('wan','wan_mac_tr1')
        self.__link_local_addr = self.__config.get('wan','link_local_addr')
        self.__all_nodes_addr = self.__config.get('multicast','all_nodes_addr')
        self.__test_desc = self.__config.get('tests','3.2.3b')
        self.__t_lan = None
        self.__finish_wan = False
        self.part2_lan_start = False
        self.__dhcp_renew_done = False
        self.stop_ping_OK = False
        self.__config_setup_lan = ConfigSetup1_1_Lan(self.__config,self.__lan_device)



    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t3.2.3a','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t3.2.3a','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t3.2.3a','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t3.2.3a','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t3.2.3a','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t3.2.3a','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t3.2.3a','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t3.2.3a','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t3.2.3a','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t3.2.3a','routerlifetime'))
        self.__config_setup1_1.set_reachabletime(self.__config.get('t3.2.3a','reach_time'))
        self.__config_setup1_1.set_retranstimer(self.__config.get('t3.2.3a','retrans_time'))        
        self.__config_setup1_1.set_intervalo(self.__config.get('t1.6.6b','intervalo'))
        self.__config_setup1_1.set_prefix_addr(self.__config.get('setup1-1_advertise','ia_pd_address'))
        self.__config_setup1_1.set_dhcp_t1(self.__config.get('t3.2.3a','dhcp_t1'))
        self.__config_setup1_1.set_dhcp_t2(self.__config.get('t3.2.3a','dhcp_t2'))
        self.__config_setup1_1.set_dhcp_preflft(self.__config.get('t3.2.3a','dhcp_preflft'))
        self.__config_setup1_1.set_dhcp_validlft(self.__config.get('t3.2.3a','dhcp_validlft'))
        self.__config_setup1_1.set_dhcp_plen(self.__config.get('t3.2.3a','dhcp_plen'))
   
    def set_flags_lan(self):
        self.__config_setup_lan.set_elapsetime(self.__config.get('solicitlan','elapsetime'))
        self.__config_setup_lan.set_xid(self.__config.get('solicitlan','xid'))
        self.__config_setup_lan.set_fdqn(self.__config.get('solicitlan','clientfqdn'))
        self.__config_setup_lan.set_vendor_class(self.__config.get('solicitlan','vendorclass'))

        self.__config_setup_lan.set_enterprise(self.__config.get('solicitlan','enterpriseid'))
        self.__config_setup_lan.set_client_duid(self.__config.get('solicitlan','duid'))
        self.__config_setup_lan.set_iaid(self.__config.get('solicitlan','iaid'))




    def ping_unreac_ip(self):
        if self.__config_setup1_1.get_mac_ceRouter() != None:
            #print('6')
            self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','global_wan_addr'))
            self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac'))
            self.__config_setup_lan.set_ether_dst(self.__config_setup_lan.get_mac_ceRouter())
            self.__config_setup_lan.set_ipv6_dst(self.__config.get('t3.2.3b','unreachable_ip'))
            self.__sendmsgs.send_echo_request_lan(self.__config_setup_lan)
        
    def run_Lan(self):
        #self.__config_setup_lan_.flags_partA()
        logging.info('Thread da LAN inicio')
        t_test = 0
        t_test1= 0
        time_p = 0
        sent_reconfigure = False
        time_over = False
        send_ra = False
        send_na_lan = False
        reset_test1 = False
        self.set_flags_lan()
        self.__config_setup_lan.set_setup_lan_start()
        while not self.__queue_lan.full():
            if self.__queue_lan.empty():
                if t_test < 30:
 
                    time.sleep(1)
                    t_test = t_test + 1
                    if t_test % 5 ==0:
                        #print('0')
                        #print('ENVIO RS - 1 LAN')
                        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
                        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                        self.__config_setup_lan.set_ether_dst('33:33:00:01:00:02')
                        self.__config_setup_lan.set_ipv6_dst(self.__config.get('multicast','all_routers_addr'))
                        self.__config_setup_lan.set_xid(self.__config.get('informationlan','xid'))
                        #self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
                        self.__config_setup_lan.set_elapsetime(self.__config.get('informationlan','elapsetime'))
                        self.__config_setup_lan.set_vendor_class(self.__config.get('informationlan','vendorclass'))
                        self.__sendmsgs.send_dhcp_information(self.__config_setup_lan)
                        

                        #self.__config_setup_lan.set_setup_lan_start()
                        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
                        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                        self.__config_setup_lan.set_ether_dst(self.__config.get('multicast','all_mac_routers'))
                        self.__config_setup_lan.set_ipv6_dst(self.__config.get('general','all_routers_address'))
                        self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
                        self.__sendmsgs.send_icmp_rs(self.__config_setup_lan)

                        # if self.__config_setup_lan.get_mac_ceRouter() != None:
                        #     #print('6')
                        #     self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','global_wan_addr'))
                        #     self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                        #     self.__config_setup_lan.set_ether_dst(self.__config_setup_lan.get_mac_ceRouter())
                        #     self.__config_setup_lan.set_ipv6_dst(self.__config.get('wan','global_wan_addr'))
                        #     self.__sendmsgs.send_echo_request_lan(self.__config_setup_lan)
                            
                        # self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
                        # self.__config_setup_lan.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
                        # self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                        # self.__config_setup_lan.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
                        # #self.set_tgt(self.get_local_addr_ceRouter())
                        
                        # self.__config_setup_lan.set_tgt(self.__config.get('wan','link_local_addr'))
                        # #self.__sendmsgssetup1_1.send_echo_request(self)
                        # self.__config_setup_lan.set_lla(self.__config.get('wan','link_local_mac'))
                        # self.__sendmsgs.send_icmp_ns_lan(self.__config_setup_lan)
                        #print('1')

                    logging.info('Thread da LAN time')
                    time.sleep(1)
                else:
                    time_over = True

#                    t_test = t_test + 1
 #                   if self.__config_setup1_1.get_recvd_dhcp_renew():
                #pkt = self.__queue_lan.get()
            else:

                pkt = self.__queue_lan.get()

                if pkt.haslayer(ICMPv6ND_RA):
                    self.__config_setup_lan.set_mac_ceRouter(pkt[Ether].src)

                if pkt.haslayer(ICMPv6MLReport2):
                    self.__config_setup_lan.set_mac_ceRouter(pkt[Ether].src)

                if pkt.haslayer(DHCP6_Reply):
                    self.__config_setup_lan.set_mac_ceRouter(pkt[Ether].src)

                if pkt[Ether].src == self.__config.get('lan','mac_address'):
                    continue

                if pkt.haslayer(ICMPv6ND_NS):


                    if pkt[ICMPv6ND_NS].tgt == self.__config.get('lan','global_wan_addr'):
                        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','global_wan_addr'))
                        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                        self.__config_setup_lan.set_ether_dst(pkt[Ether].src)
                        self.__config_setup_lan.set_ipv6_dst(pkt[IPv6].src)
                        self.__config_setup_lan.set_tgt(self.__config.get('lan','global_wan_addr'))
                        self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
                        self.__config_setup_lan.set_mac_ceRouter(pkt[Ether].src)
                        self.__sendmsgs.send_icmp_na_lan(self.__config_setup_lan)
                    print('AQUI-9')
                    if pkt[ICMPv6ND_NS].tgt == self.__config.get('lan','lan_local_addr'):

                        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
                        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                        self.__config_setup_lan.set_ether_dst(pkt[Ether].src)
                        self.__config_setup_lan.set_ipv6_dst(pkt[IPv6].src)
                        self.__config_setup_lan.set_tgt(self.__config.get('lan','lan_local_addr'))
                        self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
                        self.__config_setup_lan.set_mac_ceRouter(pkt[Ether].src)
                        self.__sendmsgs.send_icmp_na_lan(self.__config_setup_lan)
                        
            if self.__config_setup1_1.get_setup1_1_OK():
                if pkt[Ether].src == self.__config.get('lan','mac_address'):
                    continue
                if t_test1 < 30:
                    t_test1 = t_test1 + 1
                    if t_test1 % 5 == 0:

                        self.ping_unreac_ip()
                    
                # if t_test1 < 30:
                #     t_test1 = t_test1 + 1
                #     if t_test1 % 5 == 0: 
                #         self.ping_tn3()
                #         print('imprimindo relogio ping')
                #         print(t_test1)       
                    if pkt.haslayer(ICMPv6DestUnreach):
                        self.__packet_sniffer_wan.stop() 
                        self.__packet_sniffer_lan.stop()
                        logging.info('Teste 3.7.2a - APROVADO. Não passou pacotes da LAN para WAN devido ao RouterLife time estar zerado')
                        return True   


                    if pkt.haslayer(ICMPv6ND_NS):

                        if pkt[ICMPv6ND_NS].tgt == self.__config.get('lan','global_wan_addr'):
                            self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','global_wan_addr'))
                            self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                            self.__config_setup_lan.set_ether_dst(pkt[Ether].src)
                            self.__config_setup_lan.set_ipv6_dst(pkt[IPv6].src)
                            self.__config_setup_lan.set_tgt(self.__config.get('lan','global_wan_addr'))
                            self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
                            self.__config_setup_lan.set_mac_ceRouter(pkt[Ether].src)
                            self.__sendmsgs.send_icmp_na_lan(self.__config_setup_lan)
                            
                        if pkt[ICMPv6ND_NS].tgt == self.__config.get('lan','lan_local_addr'):

                            self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
                            self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                            self.__config_setup_lan.set_ether_dst(pkt[Ether].src)
                            self.__config_setup_lan.set_ipv6_dst(pkt[IPv6].src)
                            self.__config_setup_lan.set_tgt(self.__config.get('lan','lan_local_addr'))
                            self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
                            self.__config_setup_lan.set_mac_ceRouter(pkt[Ether].src)
                            self.__sendmsgs.send_icmp_na_lan(self.__config_setup_lan)
                else: 
                    logging.info('Reprovado Teste 3.2.3b - Timeout e não recebeu ICMPv6 Destino Unreachable')
                    self.__packet_sniffer_wan.stop() 
                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True 
                    self.__fail_test = False
                    return False    

                

    def rourter_advertise(self):
        self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
        self.__config_setup1_1.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
        self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','ra_address'))
        self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
        self.__sendmsgs.send_tr1_RA2(self.__config_setup1_1)


    def ping(self):
        if self.__config_setup1_1.get_mac_ceRouter() != None:
            #print('6')
            self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','global_wan_addr'))
            self.__config_setup1_1.set_ether_src(self.__config.get('wan','wan_mac_tr1'))
            self.__config_setup1_1.set_ether_dst(self.__config_setup1_1.get_mac_ceRouter())
            self.__config_setup1_1.set_ipv6_dst(self.__config.get('t3.2.3a','unreachable_ip'))
            self.__sendmsgs.send_echo_request(self.__config_setup1_1)

    def neighbor_advertise_local(self,pkt):
        self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','link_local_addr'))
        self.__config_setup1_1.set_ether_src(self.__config.get('wan','wan_mac_tr1'))
        self.__config_setup1_1.set_ether_dst(pkt[Ether].src)
        self.__config_setup1_1.set_ipv6_dst(pkt[IPv6].src)
        self.__config_setup1_1.set_tgt(self.__config.get('wan','link_local_addr'))
        self.__config_setup1_1.set_lla(self.__config.get('wan','wan_mac_tr1'))
        self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)
        self.__sendmsgs.send_icmp_na(self.__config_setup1_1)

    def neighbor_advertise_global(self,pkt):
        self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','global_wan_addr'))
        self.__config_setup1_1.set_ether_src(self.__config.get('wan','wan_mac_tr1'))
        self.__config_setup1_1.set_ether_dst(pkt[Ether].src)
        self.__config_setup1_1.set_ipv6_dst(pkt[IPv6].src)
        self.__config_setup1_1.set_tgt(self.__config.get('wan','global_wan_addr'))
        self.__config_setup1_1.set_lla(self.__config.get('wan','wan_mac_tr1'))
        self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)
        self.__sendmsgs.send_icmp_na(self.__config_setup1_1)
    def neighbor_advertise_global_tn3(self,pkt):
        self.__config_setup1_1.set_ipv6_src(self.__config.get('t3.2.3a','tn3_ip'))
        self.__config_setup1_1.set_ether_src(self.__config.get('t3.2.3a','tn3_mac'))
        self.__config_setup1_1.set_ether_dst(pkt[Ether].src)
        self.__config_setup1_1.set_ipv6_dst(pkt[IPv6].src)
        self.__config_setup1_1.set_tgt(self.__config.get('t3.2.3a','tn3_ip'))
        self.__config_setup1_1.set_lla(self.__config.get('t3.2.3a','tn3_mac'))
        self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)
        self.__sendmsgs.send_icmp_na(self.__config_setup1_1)

    def run(self):
        self.__t_lan =  Thread(target=self.run_Lan,name='LAN_Thread')
        self.__t_lan.start()
        
        self.__packet_sniffer_wan = PacketSniffer('Test273b-WAN',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()
        
        self.__packet_sniffer_lan = PacketSniffer('Test273b-LAN',self.__queue_lan,self,self.__config,self.__lan_device)
        test_lan = self.__packet_sniffer_lan.start()
        self.__config_setup1_1.set_ra2()
        self.set_flags()
        logging.info(self.__test_desc)
        t_test = 0
        time1 = 0
        sent_reconfigure = False
        time_over = False
        start_time_count = False
        finish_wan = False
        part1_OK = False
        self.__config_setup1_1.set_pd_prefixlen(self.__config.get('t3.2.3a','pd_prefixlen')) 
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t3.2.3a','routerlifetime')) 
        while not self.__queue_wan.full():
            if self.__queue_wan.empty():
                if t_test <= 300:
                    time.sleep(1)
                    t_test = t_test + 1
                    if t_test % 10 == 0:
                        self.rourter_advertise()
                        #self.ping()
                    
                    if start_time_count:
                        if time1 < 600:
                            time1 = time1 + 1
                            # print('imprimindo relogio')
                            # print(time1)
                                #if time1 % 5 == 0: 
                                #self.ping()


                else:
                    time_over = True      
            else:
                pkt = self.__queue_wan.get()

                if not self.__config_setup1_1.get_ND_local_OK():

                    if pkt[Ether].src == self.__config.get('wan','link_local_mac'):
                        print('ND_LOCAL,continue')
                        continue

                    if pkt[Ether].src == self.__config.get('wan','ra_mac'):
                        print('ND_LOCAL-A,continue')                        
                        continue


                    if pkt.haslayer(ICMPv6ND_RS):
                  
                        if pkt[Ether].src == self.__config.get('wan','link_local_mac'):
                            print('RS,continue')         
                            continue

                        if pkt[Ether].src == self.__config.get('wan','ra_mac'):
                            print('RS-A,continue')                                     
                            continue

                        self.__config_setup1_1.set_local_addr_ceRouter(pkt[IPv6].src)
                        self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)    
                        #self.__config_setup1_1.set_ND_local_OK()

                    if pkt.haslayer(DHCP6_Solicit):
                        if pkt[Ether].src == self.__config.get('wan','link_local_mac'):
                            print('solicit,continue')
                            continue

                        if pkt[Ether].src == self.__config.get('wan','ra_mac'):
                            print('solicitA,continue')
                            continue
                        self.__config_setup1_1.set_local_addr_ceRouter(pkt[IPv6].src)
                        self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)
                        #self.__config_setup1_1.set_ND_local_OK()  

                if pkt.haslayer(ICMPv6ND_NS):

                    if pkt[ICMPv6ND_NS].tgt == self.__config.get('wan','global_wan_addr'):
                        self.neighbor_advertise_global(pkt)
                        
                    if pkt[ICMPv6ND_NS].tgt == self.__config.get('wan','link_local_addr'):
                        self.neighbor_advertise_local(pkt)



                #pkt = self.__queue_wan.get()
                if not self.__config_setup1_1.get_setup1_1_OK():
                    print('test1')
                    if not self.__config_setup1_1.get_disapproved():
                        print('test2')
                        self.__config_setup1_1.run_setup1_1(pkt)
                        print('test3')
                        if pkt.haslayer(ICMPv6ND_RS):

                            if pkt[Ether].src == self.__config.get('wan','link_local_mac'):
                                print('RS-2,continue')         
                                continue
                            if pkt[Ether].src == self.__config.get('wan','ra_mac'):
                                print('RS-2A,continue')
                                continue
                            print('test4')
                            #self.__config_setup1_1.set_ND_local_OK()
                            self.__config_setup1_1.set_local_addr_ceRouter(pkt[IPv6].src)
                            self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)                                 
                            self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
                            self.__config_setup1_1.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
                            self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','ra_address'))
                            self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
                            self.__sendmsgs.send_tr1_RA2(self.__config_setup1_1)

                    else:
                        logging.info('Reprovado Teste 2.7.3b - Falha em completar o Common Setup 1.1 da RFC')
                        self.__packet_sniffer_wan.stop() 
                        return False

                else:

                    if not self.__finish_wan:
                        start_time_count = True
                        if time1 < 50:
                            
                            if pkt.haslayer(ICMPv6EchoRequest):

                                logging.info('Reprovado Teste 2.7.3b - Recebeu ICMPv6EchoRequest de um endereço inalcançavel')
                                self.__packet_sniffer_wan.stop() 
                                self.__packet_sniffer_lan.stop()
                                self.__finish_wan = True 
                                self.__fail_test = False
                                return False
                                #print('AQUI-2.0')

                            if pkt.haslayer(ICMPv6ND_NS):
                                if pkt[ICMPv6ND_NS].tgt == self.__config.get('wan','global_wan_addr'):
                                    print('glboal')
                                    self.neighbor_advertise_global(pkt)

                                if pkt[ICMPv6ND_NS].tgt == self.__config.get('wan','ra_address'):
                                    print('local')
                                    self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','ra_address'))
                                    self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
                                    self.__config_setup1_1.set_ether_dst(pkt[Ether].src)
                                    self.__config_setup1_1.set_ipv6_dst(pkt[IPv6].src)
                                    self.__config_setup1_1.set_tgt(self.__config.get('wan','ra_address'))
                                    self.__config_setup1_1.set_lla(self.__config.get('wan','ra_mac'))
                                    self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)
                                    self.__sendmsgs.send_icmp_na(self.__config_setup1_1)







                            #if time1 % 5 == 0: 
                                #self.ping()
                            # if part1_OK == False:
                            #     if pkt.haslayer(ICMPv6EchoRequest):

                            #     #logging.info('Reprovado Teste 2.7.3a - Recebido ICMPv6EchoRequest na WAN sendo que Routerlifime anunciado é zero')
                            #         part1_OK = True

                            # if self.part2_lan_start:
                            #     if pkt.haslayer(ICMPv6EchoRequest):
                            #         logging.info('Reprovado Teste 2.7.3a - Recebido ICMPv6EchoRequest na WAN sendo que Routerlifime anunciado é zero')
                            #         self.__packet_sniffer_wan.stop() 
                            #         self.__packet_sniffer_lan.stop()
                            #         self.__finish_wan = True 
                            #         self.__fail_test = False
                            #         return False
                            # if part1_OK and not self.part2_lan_start:
                            #     print('enviado1')
                            #     self.__config_setup1_1.set_routerlifetime('0')
                            #     self.__config_setup1_1.set_reachabletime('0')
                            #     self.__config_setup1_1.set_retranstimer('0') 

                            #     self.__sendmsgs.send_tr1_RA2(self.__config_setup1_1)
                            #     print('limpando')
                            #     while not self.stop_ping_OK:
                            #         time.sleep(1)
                            #         print('aguardando terminar')
                                    
                            #     time.sleep(10)
                            #     while not self.__queue_wan.empty():
                            #         self.__queue_wan.get()
                                
                            #     print('enviando 3')
                            #     for x in range(3):
                            #         time.sleep(1)
                            #         x = x+1
                            #         self.__sendmsgs.send_tr1_RA2(self.__config_setup1_1)
                            #     self.part2_lan_start = True

                            # if pkt.haslayer(ICMPv6ND_NS):
                            #     if pkt[ICMPv6ND_NS].tgt == self.__config.get('t3.2.3a','tn3_ip'):
                            #         print('glboal')
                            #         self.neighbor_advertise_global_tn3(pkt)

                            #     if pkt[ICMPv6ND_NS].tgt == self.__config.get('wan','ra_address'):
                            #         print('local')
                            #         self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','ra_address'))
                            #         self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
                            #         self.__config_setup1_1.set_ether_dst(pkt[Ether].src)
                            #         self.__config_setup1_1.set_ipv6_dst(pkt[IPv6].src)
                            #         self.__config_setup1_1.set_tgt(self.__config.get('wan','ra_address'))
                            #         self.__config_setup1_1.set_lla(self.__config.get('wan','ra_mac'))
                            #         self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)
                            #         self.__sendmsgs.send_icmp_na(self.__config_setup1_1)
                                    
                        else:            
                            self.__packet_sniffer_wan.stop() 
                            self.__packet_sniffer_lan.stop()
                            logging.info('Teste 3.7.3 - Reprovado. Time out sem mensagem Unreacheable')
                            return True        
                    else:
                        self.__packet_sniffer_wan.stop()
                        if self.__fail_test:
                            return False
                        else:
                                return True
        self.__packet_sniffer_wan.stop()
        return False
     
        