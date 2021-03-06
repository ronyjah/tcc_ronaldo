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
from duplicatefilter import DuplicateFilter
from flask import Flask,send_file,g,current_app,session
import time
from flask_cors import CORS
import requests

import logging

import json
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
# app = Flask(__name__)
format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")
logging = logging.getLogger(__name__)
d = DuplicateFilter(logging)
logging.addFilter(d)




class Test324:

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
        self.__test_desc = self.__config.get('tests','3.2.4')
        self.__t_lan = None
        self.__finish_wan = False
        self.part2_lan_start = False
        self.__dhcp_renew_done = False
        self.stop_ping_OK = False
        self.ipsrc = None
        self.__app = app
        self.msg = self.__config.get('tests','3.2.4')
        self.msg_lan =self.__config.get('tests','3.2.4')
        self.__config_setup_lan = ConfigSetup1_1_Lan(self.__config,self.__lan_device)

    def set_flags(self):
        logging.info('WAN: Setup1.1 concluido. Contador de 300 s iniciado afim de concluir o teste')
        self.__config_setup1_1.set_flag_M(self.__config.get('t3.2.4','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t3.2.4','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t3.2.4','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t3.2.4','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t3.2.4','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t3.2.4','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t3.2.4','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t3.2.4','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t3.2.4','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t3.2.4','routerlifetime'))
        self.__config_setup1_1.set_reachabletime(self.__config.get('t3.2.4','reach_time'))
        self.__config_setup1_1.set_retranstimer(self.__config.get('t3.2.4','retrans_time'))        
        self.__config_setup1_1.set_intervalo(self.__config.get('t1.6.6b','intervalo'))
        self.__config_setup1_1.set_prefix_addr(self.__config.get('setup1-1_advertise','ia_pd_address'))
        self.__config_setup1_1.set_dhcp_t1(self.__config.get('t3.2.4','dhcp_t1'))
        self.__config_setup1_1.set_dhcp_t2(self.__config.get('t3.2.4','dhcp_t2'))
        self.__config_setup1_1.set_dhcp_preflft(self.__config.get('t3.2.4','dhcp_preflft'))
        self.__config_setup1_1.set_dhcp_validlft(self.__config.get('t3.2.4','dhcp_validlft'))
        self.__config_setup1_1.set_dhcp_plen(self.__config.get('t3.2.4','dhcp_plen'))
   
    def set_flags_lan(self):
        self.__config_setup_lan.set_elapsetime(self.__config.get('solicitlan','elapsetime'))
        self.__config_setup_lan.set_xid(self.__config.get('solicitlan','xid'))
        self.__config_setup_lan.set_fdqn(self.__config.get('solicitlan','clientfqdn'))
        self.__config_setup_lan.set_vendor_class(self.__config.get('solicitlan','vendorclass'))
        self.__config_setup_lan.set_enterprise(self.__config.get('solicitlan','enterpriseid'))
        self.__config_setup_lan.set_client_duid(self.__config.get('solicitlan','duid'))
        self.__config_setup_lan.set_iaid(self.__config.get('solicitlan','iaid'))

    def ping_tn1_ula(self):
        if self.__config_setup1_1.get_mac_ceRouter() != None:
            self.ipsrc = self.__config.get('t3.2.4','prefix_ula') + self.__config.get('t3.2.4','sufix_ula')
            self.__config_setup_lan.set_ipv6_src(self.ipsrc)
            self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac'))
            self.__config_setup_lan.set_ether_dst(self.__config_setup_lan.get_mac_ceRouter())
            self.__config_setup_lan.set_ipv6_dst(self.__config.get('wan','global_wan_addr'))
            self.__sendmsgs.send_echo_request_lan(self.__config_setup_lan)
        
    def send_dhcp_information(self):
        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_ether_dst('33:33:00:01:00:02')
        self.__config_setup_lan.set_ipv6_dst(self.__config.get('multicast','all_routers_addr'))
        self.__config_setup_lan.set_xid(self.__config.get('informationlan','xid'))
        self.__config_setup_lan.set_elapsetime(self.__config.get('informationlan','elapsetime'))
        self.__config_setup_lan.set_vendor_class(self.__config.get('informationlan','vendorclass'))
        self.__sendmsgs.send_dhcp_information(self.__config_setup_lan)

    def send_rs_lan(self):
        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_ether_dst(self.__config.get('multicast','all_mac_routers'))
        self.__config_setup_lan.set_ipv6_dst(self.__config.get('general','all_routers_address'))
        self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
        self.__sendmsgs.send_icmp_rs(self.__config_setup_lan)

    def send_global_na_lan(self,pkt):
        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','global_wan_addr'))
        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_ether_dst(pkt[Ether].src)
        self.__config_setup_lan.set_ipv6_dst(pkt[IPv6].src)
        self.__config_setup_lan.set_tgt(self.__config.get('lan','global_wan_addr'))
        self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_mac_ceRouter(pkt[Ether].src)
        self.__sendmsgs.send_icmp_na_lan(self.__config_setup_lan)

    def send_local_na_lan(self,pkt):
        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_ether_dst(pkt[Ether].src)
        self.__config_setup_lan.set_ipv6_dst(pkt[IPv6].src)
        self.__config_setup_lan.set_tgt(self.__config.get('lan','lan_local_addr'))
        self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_mac_ceRouter(pkt[Ether].src)
        self.__sendmsgs.send_icmp_na_lan(self.__config_setup_lan)

    def rourter_advertise(self):
        self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
        self.__config_setup1_1.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
        self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','ra_address'))
        self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
        self.__sendmsgs.send_tr1_RA2(self.__config_setup1_1)

    def ping(self):
        if self.__config_setup1_1.get_mac_ceRouter() != None:
            self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','global_wan_addr'))
            self.__config_setup1_1.set_ether_src(self.__config.get('wan','wan_mac_tr1'))
            self.__config_setup1_1.set_ether_dst(self.__config_setup1_1.get_mac_ceRouter())
            self.__config_setup1_1.set_ipv6_dst(self.__config.get('t3.2.4','unreachable_ip'))
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
        self.__config_setup1_1.set_ipv6_src(self.__config.get('t3.2.4','tn3_ip'))
        self.__config_setup1_1.set_ether_src(self.__config.get('t3.2.4','tn3_mac'))
        self.__config_setup1_1.set_ether_dst(pkt[Ether].src)
        self.__config_setup1_1.set_ipv6_dst(pkt[IPv6].src)
        self.__config_setup1_1.set_tgt(self.__config.get('t3.2.4','tn3_ip'))
        self.__config_setup1_1.set_lla(self.__config.get('t3.2.4','tn3_mac'))
        self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)
        self.__sendmsgs.send_icmp_na(self.__config_setup1_1)

    def set_status_lan(self,v):
        self.msg_lan = v

    def get_status_lan(self):
        return self.msg_lan

    def run_Lan(self):
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
        cache_lan = []

        @self.__app.route("/LAN",methods=['GET'])
        def envia_lan():
            return self.get_status_lan()

        while not self.__queue_lan.full():
            if self.__queue_lan.empty():
                if t_test < 30:
                    time.sleep(1)
                    t_test = t_test + 1
                    if t_test % 5 ==0:
                        self.set_status_lan('LAN: Transmissões de RS e DHCP information por 30 s a cada 5 seg.')
                        logging.info('LAN: Inicio das transmissões de RS e DHCP information por 30 s.')
                        self.send_dhcp_information()
                        self.send_rs_lan()
                    time.sleep(1)
                else:
                    time_over = True
            else:
                pkt = self.__queue_lan.get()
                cache_lan.append(pkt)
                wrpcap("lan-3.2.4.cap",cache_lan)
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
                        self.send_global_na_lan(pkt)

                    if pkt[ICMPv6ND_NS].tgt == self.__config.get('lan','lan_local_addr'):
                        self.send_local_na_lan(pkt)
                        
            if self.__config_setup1_1.get_setup1_1_OK():
                self.set_status_lan('LAN: Setup1.1 concluido. Contador de 300 s iniciado afim de concluir o teste')
                logging.info('LAN: Setup1.1 concluido. Contador de 300 s iniciado afim de concluir o teste')
                if pkt[Ether].src == self.__config.get('lan','mac_address'):
                    continue
                if t_test1 < 300:
                    t_test1 = t_test1 + 1
                    if t_test1 % 5 == 0:
                        self.set_status_lan('LAN:Fim do setup 1.1. Enviando ICMPv6 RS')
                        self.send_rs_lan()

                    if pkt.haslayer(ICMPv6ND_RA):
                        if pkt[ICMPv6NDOptPrefixInfo].prefix == self.__config.get('t3.2.4','prefix_ula'):
                                logging.info('LAN: Recebido prefixo esperado. Inciando tentativa de Pingar um endereco Global')
                                self.set_status_lan('LAN: Recebido prefixo esperado. Inciando tentativa de Pingar um endereco Global')
                                time.sleep(2)
                                self.ping_tn1_ula()
                        else:
                            self.__finish_wan = True
                            self.__fail_test = True 
                            self.__packet_sniffer_wan.stop() 
                            self.__packet_sniffer_lan.stop()
                            self.set_status_lan('Teste 3.2.4 - FALHA. VERIFIQUE O PREFIXO ULA CONFIGURADO NO ROTEADOR')
                            time.sleep(2)
                            logging.info('Teste 3.2.4 - FALHA. VERIFIQUE O PREFIXO ULA CONFIGURADO NO ROTEADOR')
                            self.set_status_lan('REPROVADO')

                            print(pkt[ICMPv6NDOptPrefixInfo].prefix)
                            return False   
     
                    if pkt.haslayer(ICMPv6DestUnreach):
                        self.__finish_wan = True
                        self.__fail_test = False
                        #self.__packet_sniffer_wan.stop() 
                        self.__packet_sniffer_lan.stop()
                        self.set_status_lan('APROVADO')
                        logging.info('TEST 3.2.4: UNIQUE LOCAL ADDRESS FORWARDING....APROVADO')
                        return True   

                    if pkt.haslayer(ICMPv6ND_NS):
                        if pkt[ICMPv6ND_NS].tgt == self.__config.get('lan','global_wan_addr'):
                            self.send_global_na_lan(pkt)
                            
                        if pkt[ICMPv6ND_NS].tgt == self.__config.get('lan','lan_local_addr'):
                            self.send_local_na_lan(pkt)

                        if pkt[ICMPv6ND_NS].tgt == self.ipsrc:
                            self.set_status_lan('LAN: Recebido NS target Local: enviando ICMP NA local')
                            self.__config_setup_lan.set_ipv6_src(self.ipsrc)
                            self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                            self.__config_setup_lan.set_ether_dst(pkt[Ether].src)
                            self.__config_setup_lan.set_ipv6_dst(pkt[IPv6].src)
                            self.__config_setup_lan.set_tgt(self.ipsrc)
                            self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
                            self.__config_setup_lan.set_mac_ceRouter(pkt[Ether].src)
                            self.__sendmsgs.send_icmp_na_lan(self.__config_setup_lan)

                else: 
                    self.set_status_lan('Nao foi recebido a mensagem Destino Inalcançável durante a execução do teste')
                    time.sleep(2)
                    self.set_status_lan('REPROVADO')

                    logging.info('TEST 3.2.4: UNIQUE LOCAL ADDRESS FORWARDING....REPROVADO')
                    logging.info('Nao foi recebido a mensagem Destino Inalcançável durante a execução do teste')
                    self.__packet_sniffer_wan.stop() 
                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True 
                    self.__fail_test = False
                    return False    

    def set_status(self,v):
        self.msg = v

    def get_status(self):
        return self.msg
    def run(self):
        
        self.set_status('Ative a ULA com prefixo: ' +  self.__config.get('t3.2.4','prefix_ula') + ' . E reinicie o Roteador')

        @self.__app.route("/WAN",methods=['GET'])
        def enviawan():
            return self.get_status()

        logging.info(self.__test_desc)
        logging.info('==================================================================================================')
        logging.info('Ative a ULA com prefixo: ' +  self.__config.get('t3.2.4','prefix_ula') + ' . E reinicie o Roteador') 
        logging.info('===================================================================================================')        
        time.sleep(10)
        self.__t_lan =  Thread(target=self.run_Lan,name='LAN_Thread')
        self.__t_lan.start()
        self.set_status('Thread LAN Criada')
        self.__packet_sniffer_wan = PacketSniffer('Test273b-WAN',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()
        self.set_status('Sniffer WAN Inciado')
        self.__packet_sniffer_lan = PacketSniffer('Test273b-LAN',self.__queue_lan,self,self.__config,self.__lan_device)
        self.set_status('Sniffer LAN Inciado')
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
        cache_wan = []
        self.__config_setup1_1.set_pd_prefixlen(self.__config.get('t3.2.4','pd_prefixlen')) 
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t3.2.4','routerlifetime')) 
        self.set_status('WAN: Tráfego Iniciado')
        while not self.__queue_wan.full():
            if self.__queue_wan.empty():
                
                if t_test <= 300:
                    time.sleep(1)
                    t_test = t_test + 1
                    if t_test % 10 == 0:
                        self.set_status('WAN: Transmissão de ICMP RA periódico')
                        logging.info('WAN: Inicio das transmissoes de Router Advertisment')
                        self.rourter_advertise()
                    
                    if start_time_count:
                        self.set_status('Setup 1.1 concluido')
                        logging.info('WAN: Inicio do novo temporizador. Setup 1.1 concluido')
                        if time1 < 600:
                            time1 = time1 + 1

                else:
                    self.__packet_sniffer_wan.stop() 
                    self.__packet_sniffer_lan.stop()
                    self.set_status('Timeout')
                    time.sleep(2)
                    self.set_status('REPROVADO')
                    time_over = True      
            else:
                
                pkt = self.__queue_wan.get()
                cache_wan.append(pkt)
                wrpcap("WAN-3.2.4.cap",cache_wan)
                if not self.__config_setup1_1.get_ND_local_OK():
                    self.set_status('WAN: Setup 1.1 em execução')
                    logging.info('WAN: Inicio do setup 1.1. Pode demorar para concluir')
                    if pkt[Ether].src == self.__config.get('wan','link_local_mac'):
                        continue

                    if pkt[Ether].src == self.__config.get('wan','ra_mac'):
                        continue

                    if pkt.haslayer(ICMPv6ND_RS):
                        self.set_status('WAN: Recebido ICMPv6_RS')
                        if pkt[Ether].src == self.__config.get('wan','link_local_mac'):
                            continue

                        if pkt[Ether].src == self.__config.get('wan','ra_mac'):
                            continue
                        
                        self.__config_setup1_1.set_local_addr_ceRouter(pkt[IPv6].src)
                        self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)    

                    if pkt.haslayer(DHCP6_Solicit):
                        self.set_status('WAN: Recebido DHCP6 Solicit')
                        if pkt[Ether].src == self.__config.get('wan','link_local_mac'):
                            continue

                        if pkt[Ether].src == self.__config.get('wan','ra_mac'):
                            continue
                        self.__config_setup1_1.set_local_addr_ceRouter(pkt[IPv6].src)
                        self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)

                if pkt.haslayer(ICMPv6ND_NS):
                    self.set_status('WAN: Recebido ICMPv6 NS')
                    if pkt[ICMPv6ND_NS].tgt == self.__config.get('wan','global_wan_addr'):
                        logging.info('WAN: Solicitado ICMP_NS para um target Global. Enviando NA global do host')
                        self.neighbor_advertise_global(pkt)
                        
                    if pkt[ICMPv6ND_NS].tgt == self.__config.get('wan','link_local_addr'):
                        logging.info('WAN: Solicitado ICMP_NS para um target local. Enviando NA local host')
                        self.neighbor_advertise_local(pkt)

                if not self.__config_setup1_1.get_setup1_1_OK():
                    self.set_status('WAN: Setup 1.1 em execução')
                    if not self.__config_setup1_1.get_disapproved():
                        self.__config_setup1_1.run_setup1_1(pkt)
                        if pkt.haslayer(ICMPv6ND_RS):
                            if pkt[Ether].src == self.__config.get('wan','link_local_mac'):
                                continue
                            if pkt[Ether].src == self.__config.get('wan','ra_mac'):
                                continue
                            self.set_status('WAN: Setup 1.1 Recebido ICMP RS, enviado RA')
                            self.__config_setup1_1.set_local_addr_ceRouter(pkt[IPv6].src)
                            self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)                                 
                            self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
                            self.__config_setup1_1.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
                            self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','ra_address'))
                            self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
                            logging.info('Solicitado ICMP_RS. Enviando RA_ver2')
                            self.__sendmsgs.send_tr1_RA2(self.__config_setup1_1)

                    else:
                        self.set_status('WAN: Reprovado Teste 3.2.4 - Falha em completar o Common Setup 1.1 da RFC')
                        self.set_status('REPROVADO')
                        logging.info('WAN: Reprovado Teste 3.2.4 - Falha em completar o Common Setup 1.1 da RFC')
                        self.__packet_sniffer_wan.stop() 
                        return False

                else:
                    self.set_status('WAN: Setup 1.1 Finalizado. Iniciando novo contador de tempo. O teste termina em 300 seg se a mensagem aguardada nao for recebida')
                    logging.info('WAN: Setup 1.1 Finalizado. Iniciando novo contador de tempo. O teste termina em 300 seg se a mensagem aguardada nao for recebida')
                    if not self.__finish_wan:
                        start_time_count = True
                        if time1 < 300:
                            
                            if pkt.haslayer(ICMPv6EchoRequest):
                                logging.info('WAN: TEST 3.2.4: UNIQUE LOCAL ADDRESS FORWARDING....REPROVADO')
                                logging.info('WAN: Indevido recebimento de Echo Request na WAN de um IP proveniente pela ULA do roteador atribuido aos hosts na LAN')
                                self.set_status('WAN: Indevido recebimento de Echo Request na WAN de um IP gerado pela ULA do roteador aos hosts na LAN')
                                time.sleep(2)
                                self.set_status('REPROVADO')
                                self.__packet_sniffer_wan.stop() 
                                self.__packet_sniffer_lan.stop()
                                self.__finish_wan = True 
                                return False

                            if pkt.haslayer(ICMPv6ND_NS):
                                if pkt[ICMPv6ND_NS].tgt == self.__config.get('wan','global_wan_addr'):
                                    self.neighbor_advertise_global(pkt)

                                if pkt[ICMPv6ND_NS].tgt == self.__config.get('wan','ra_address'):
                                    self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','ra_address'))
                                    self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
                                    self.__config_setup1_1.set_ether_dst(pkt[Ether].src)
                                    self.__config_setup1_1.set_ipv6_dst(pkt[IPv6].src)
                                    self.__config_setup1_1.set_tgt(self.__config.get('wan','ra_address'))
                                    self.__config_setup1_1.set_lla(self.__config.get('wan','ra_mac'))
                                    self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)
                                    self.__sendmsgs.send_icmp_na(self.__config_setup1_1)
                        else:            
                            self.__packet_sniffer_wan.stop() 
                            self.__packet_sniffer_lan.stop()
                            #return send_file('/home/ronaldo/tcc_oficial/tcc_ronaldo/lan.cap', attachment_filename='lan.cap')
                            self.set_status('WAN: Time out sem mensagem Unreacheable na interface LAN')
                            time.sleep(2)
                            self.set_status('REPROVADO')
                            logging.info('WAN: TEST 3.2.4: UNIQUE LOCAL ADDRESS FORWARDING....REPROVADO')
                            logging.info('WAN: Time out sem mensagem Unreacheable na interface LAN')
                            return True        
                    else:
                        self.__packet_sniffer_wan.stop()
                        if self.__fail_test:
                            return False
                        else:
                                return True
        self.__packet_sniffer_wan.stop()
        return False
     
        