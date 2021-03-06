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

class Test321a:

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
        self.__test_desc = self.__config.get('tests','3.2.1a')
        self.__t_lan = None
        self.__finish_wan = False
        self.__dhcp_renew_done = False
        self.msg = self.__config.get('tests','3.2.1a')
        self.msg_lan =self.__config.get('tests','3.2.1a')
        self.__config_setup_lan = ConfigSetup1_1_Lan(self.__config,self.__lan_device)



    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t3.2.1a','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t3.2.1a','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t3.2.1a','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t3.2.1a','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t3.2.1a','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t3.2.1a','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t3.2.1a','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t3.2.1a','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t3.2.1a','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t3.2.1a','routerlifetime'))
        self.__config_setup1_1.set_reachabletime(self.__config.get('t3.2.1a','reach_time'))
        self.__config_setup1_1.set_retranstimer(self.__config.get('t3.2.1a','retrans_time'))        
        self.__config_setup1_1.set_intervalo(self.__config.get('t1.6.6b','intervalo'))
        self.__config_setup1_1.set_prefix_addr(self.__config.get('setup1-1_advertise','ia_pd_address'))
        self.__config_setup1_1.set_dhcp_t1(self.__config.get('t3.2.1a','dhcp_t1'))
        self.__config_setup1_1.set_dhcp_t2(self.__config.get('t3.2.1a','dhcp_t2'))
        self.__config_setup1_1.set_dhcp_preflft(self.__config.get('t3.2.1a','dhcp_preflft'))
        self.__config_setup1_1.set_dhcp_validlft(self.__config.get('t3.2.1a','dhcp_validlft'))
        self.__config_setup1_1.set_dhcp_plen(self.__config.get('t3.2.1a','dhcp_plen'))
   
    def set_flags_lan(self):
        self.__config_setup_lan.set_elapsetime(self.__config.get('solicitlan','elapsetime'))
        self.__config_setup_lan.set_xid(self.__config.get('solicitlan','xid'))
        self.__config_setup_lan.set_fdqn(self.__config.get('solicitlan','clientfqdn'))
        self.__config_setup_lan.set_vendor_class(self.__config.get('solicitlan','vendorclass'))

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

    def dhcp_information_lan(self):
        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_ether_dst('33:33:00:01:00:02')
        self.__config_setup_lan.set_ipv6_dst(self.__config.get('multicast','all_routers_addr'))
        self.__config_setup_lan.set_xid(self.__config.get('informationlan','xid'))
        self.__config_setup_lan.set_elapsetime(self.__config.get('informationlan','elapsetime'))
        self.__config_setup_lan.set_vendor_class(self.__config.get('informationlan','vendorclass'))
        self.__sendmsgs.send_dhcp_information(self.__config_setup_lan)
        
    def run_Lan(self):
        #self.__config_setup_lan_.flags_partA()

        t_test = 0
        t_test1= 0
        time_p = 0
        sent_reconfigure = False
        time_over = False
        send_ra = False
        send_na_lan = False
        self.set_flags_lan()
        self.__config_setup_lan.set_setup_lan_start()
        cache_lan = []

        @self.__app.route("/LAN",methods=['GET'])
        def envia_lan():
            return self.get_status_lan()

        while not self.__queue_lan.full():
            if self.__queue_lan.empty():
                if t_test < 50:
 
                    time.sleep(1)
                    t_test = t_test + 1
                    if t_test % 5 ==0:
                        #print('0')
                        #print('ENVIO RS - 1 LAN')
                        self.set_status_lan('LAN: Enviando DHCP information e RS periódico - MELHORAR O TESTE')
                        logging.info('LAN: Enviando DHCP information e RS periódico')
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

                        if self.__config_setup_lan.get_mac_ceRouter() != None:
                            #print('6')
                            self.set_status_lan('LAN: Enviando Echo Request para o TN1')
                            logging.info('LAN: Enviando Echo Request para o TN1')
                            self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','global_wan_addr'))
                            self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                            self.__config_setup_lan.set_ether_dst(self.__config_setup_lan.get_mac_ceRouter())
                            self.__config_setup_lan.set_ipv6_dst(self.__config.get('wan','global_wan_addr'))
                            self.__sendmsgs.send_echo_request_lan(self.__config_setup_lan)
                         

                    
                else:
                    time_over = True


            else:

                pkt = self.__queue_lan.get()
                cache_lan.append(pkt)
                wrpcap("LAN-3.2.1a.cap",cache_lan)
                if not time_over:
                    if pkt.haslayer(ICMPv6EchoReply):
                        self.set_status_lan('LAN Teste 3.2.1a - APROVADO. TN1 Respondeu ao echo request do TN2 por IP global')
                        time.sleep(2)
                        self.set_status_lan('APROVADO') # Mensagem padrão para o frontEnd atualizar Status
                        logging.info('Teste 3.2.1a - APROVADO. TN1 Respondeu ao Echo request do TN2 por IP global')

                        self.__packet_sniffer_lan.stop()
                        self.__finish_wan = True 
                        self.__fail_test = True
                        return False

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

                            self.set_status_lan('LAN: Respondendo ao NS com NA global')
                            logging.info('LAN: Respondendo ao NS com NA global')

                            self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','global_wan_addr'))
                            self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                            self.__config_setup_lan.set_ether_dst(pkt[Ether].dst)
                            self.__config_setup_lan.set_ipv6_dst(pkt[IPv6].src)
                            self.__config_setup_lan.set_tgt(self.__config.get('lan','global_wan_addr'))
                            self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))

                            self.__config_setup_lan.set_mac_ceRouter(pkt[Ether].src)
                            self.__sendmsgs.send_icmp_na_lan(self.__config_setup_lan)
                            
                        if pkt[ICMPv6ND_NS].tgt == self.__config.get('lan','lan_local_addr'):
                            self.set_status_lan('LAN: Respondendo ao NS com NA local')
                            logging.info('LAN: Respondendo ao NS com NA local')
                            self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
                            self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                            self.__config_setup_lan.set_ether_dst(pkt[Ether].dst)
                            self.__config_setup_lan.set_ipv6_dst(pkt[IPv6].src)
                            self.__config_setup_lan.set_tgt(self.__config.get('lan','lan_local_addr'))
                            self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))

                            self.__config_setup_lan.set_mac_ceRouter(pkt[Ether].src)
                            self.__sendmsgs.send_icmp_na_lan(self.__config_setup_lan)

                if self.__config_setup1_1.get_setup1_1_OK():

                    if pkt[Ether].src == self.__config.get('lan','mac_address'):

                        continue

                    if self.__config_setup_lan.get_mac_ceRouter() != None:


                        self.set_status_lan('Setup 1.1 Concluido. Enviando Echo Request para TN1')
                        logging.info('Setup 1.1 Concluido. Enviando Echo Request para TN1')

                        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','global_wan_addr'))
                        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                        self.__config_setup_lan.set_ether_dst(self.__config_setup_lan.get_mac_ceRouter())
                        self.__config_setup_lan.set_ipv6_dst(self.__config.get('wan','global_wan_addr'))
                        self.__sendmsgs.send_echo_request_lan(self.__config_setup_lan)

                    if pkt.haslayer(ICMPv6ND_NS):
                        if pkt[ICMPv6ND_NS].tgt == self.__config.get('lan','global_wan_addr'):
                            self.set_status_lan('Setup 1.1 Concluido. Respondendo ao NS do CeRouter com NA global')
                            logging.info('Setup 1.1 Concluido. Respondendo ao NS do CeRouter com NA global')

                            self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','global_wan_addr'))
                            self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                            self.__config_setup_lan.set_ether_dst(pkt[Ether].src)
                            self.__config_setup_lan.set_ipv6_dst(pkt[IPv6].src)
                            self.__config_setup_lan.set_tgt(self.__config.get('lan','global_wan_addr'))
                            self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))

                            self.__sendmsgs.send_icmp_na_lan(self.__config_setup_lan)

    def run(self):
        @self.__app.route("/WAN",methods=['GET'])
        def enviawan():
            return self.get_status()
        self.__t_lan =  Thread(target=self.run_Lan,name='LAN_Thread')
        self.__t_lan.start()
        
        self.__packet_sniffer_wan = PacketSniffer('Test321a-WAN',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()
        
        self.__packet_sniffer_lan = PacketSniffer('Test321a-LAN',self.__queue_lan,self,self.__config,self.__lan_device)
        test_lan = self.__packet_sniffer_lan.start()
        self.__config_setup1_1.set_ra2()
        self.set_flags()
        logging.info(self.__test_desc)
        t_test = 0
        sent_reconfigure = False
        time_over = False
        cache_wan = []

        finish_wan = False
        self.__config_setup1_1.set_pd_prefixlen(self.__config.get('t3.2.1a','pd_prefixlen')) 
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t3.2.1a','routerlifetime')) 
        while not self.__queue_wan.full():
            if self.__queue_wan.empty():
                if t_test <= 30:

                    time.sleep(1)
                    t_test = t_test + 1

                    if t_test % 15 ==0:
                        self.set_status('WAN: Enviando ICMP RA periódico')
                        logging.info('WAN: Enviando ICMP RA periódico')
                        self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
                        self.__config_setup1_1.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
                        self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','ra_address'))
                        self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
                        self.__sendmsgs.send_tr1_RA(self.__config_setup1_1)

                else:
                    #logging.info(' 2 Time Over')
                    time_over = True      
            else:
                pkt = self.__queue_wan.get()
                cache_wan.append(pkt)
                wrpcap("WAN-3.2.1a.cap",cache_wan)

                if pkt.haslayer(ICMPv6ND_RS):
                    if pkt[Ether].src == self.__config.get('wan','link_local_mac'):
                        #logging.info(' TEM PACOTE continue 1')
                        continue
                                    
                    if pkt[Ether].src == self.__config.get('wan','ra_mac'):
                        l#ogging.info(' TEM PACOTE continue ')
                        continue
                    #logging.info('MAC E ADDR COLETADO')   
                    #print(pkt[IPv6].src)
                    #print(pkt[Ether].src)
                    self.__config_setup1_1.set_local_addr_ceRouter(pkt[IPv6].src)
                    self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)    
                    self.__config_setup1_1.set_ND_local_OK()
                if not time_over :
                    if pkt.haslayer(ICMPv6EchoRequest):
                        self.__packet_sniffer_wan.stop()
                        self.__finish_wan = True 
                        self.__fail_test = True
                        return False
                if pkt.haslayer(DHCP6_Solicit):
                    #print(pkt[IPv6].src)
                    #print(pkt[Ether].src)
                    self.__config_setup1_1.set_local_addr_ceRouter(pkt[IPv6].src)
                    self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)
                    self.__config_setup1_1.set_ND_local_OK()   
                if time_over:
                    #logging.info('FIM DA ESPERA')
                    #time_over = True
                    pkt = self.__queue_wan.get()
                    #logging.info('FIM DA ESPERA')
                    if not self.__config_setup1_1.get_setup1_1_OK():
                        self.set_status('WAN: Setup 1.1 em execução')
                        logging.info('WAN: Setup 1.1 em execução')
                        if not self.__config_setup1_1.get_disapproved():
                            self.__config_setup1_1.run_setup1_1(pkt)
                            if pkt.haslayer(ICMPv6ND_RS):


                                if pkt[Ether].src == self.__config.get('wan','link_local_mac'):
                                    continue
                                if pkt[Ether].src == self.__config.get('wan','ra_mac'):
                                    continue
                                self.__config_setup1_1.set_ND_local_OK()
                                #if self.__local_ping_OK:
                                #print(pkt[IPv6].src)
                                self.__config_setup1_1.set_local_addr_ceRouter(pkt[IPv6].src)
                                #print(pkt[Ether].src)
                                self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src) 
                                
                                self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
                                self.__config_setup1_1.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
                                self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','ra_address'))
                                self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
                #               if not self.__active_RA_no_IA_PD:
                                #self.set_lla(self.__config.get('wan','ra_mac'))
                                #logging.info('SEND TR1 NA MAIN')
                                self.__sendmsgs.send_tr1_RA(self.__config_setup1_1)


                        else:
                            logging.info('Reprovado Teste 3.2.1a - Falha em completar o Common Setup 1.1 da RFC')
                            self.__packet_sniffer_wan.stop() 
                            return False

                    else:
                        if not self.__finish_wan:

                            if pkt.haslayer(ICMPv6EchoRequest):

                                self.__packet_sniffer_wan.stop()
                                self.__packet_sniffer_lan.stop()


                                self.set_status('Teste 3.2.1a - Recebido ICMP Request somente após IA_PD')
                                time.sleep(2)
                                self.set_status('APROVADO') # Mensagem padrão para o frontEnd atualizar Status
                                logging.info('Teste 3.2.1a - Recebido ICMP Request somente após IA_PD')

                                self.__finish_wan = True 
                                self.__fail_test = False
                                return True
                        
                            if pkt.haslayer(ICMPv6ND_NS):
                                if pkt[ICMPv6ND_NS].tgt == self.__config.get('wan','global_wan_addr'):
                                    ##print('LOOP NS')
                                    ##print(pkt[ICMPv6ND_NS].tgt)
                                    #if not send_na_lan:
                                    self.set_status('WAN: Enviando resposta ao NS com ICMP NA global')
                                    logging.info('WAN: Enviando resposta ao NS com ICMP NA global')

                                    self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','global_wan_addr'))
                                    self.__config_setup1_1.set_ether_src(self.__config.get('wan','wan_mac_tr1'))
                                    self.__config_setup1_1.set_ether_dst(pkt[Ether].src)
                                    self.__config_setup1_1.set_ipv6_dst(pkt[IPv6].src)
                                    self.__config_setup1_1.set_tgt(self.__config.get('wan','global_wan_addr'))
                                    self.__config_setup1_1.set_lla(self.__config.get('wan','wan_mac_tr1'))
                                    #send_na_lan = True
                                    self.__sendmsgs.send_icmp_na(self.__config_setup1_1)




                        else:
                            self.__packet_sniffer_wan.stop()
                            if self.__fail_test:
                                return False
                            else:
                                return True
        self.__packet_sniffer_wan.stop()
        return False
     
        