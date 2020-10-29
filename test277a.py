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

class Test277a:

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
        self.__test_desc = self.__config.get('tests','2.7.7a')
        self.__t_lan = None
        self.__finish_wan = False
        self.__dhcp_renew_done = False
        self.msg = self.__config.get('tests','2.7.7a')
        self.msg_lan =self.__config.get('tests','2.7.7a')
        self.__config_setup_lan = ConfigSetup1_1_Lan(self.__config,self.__lan_device)



    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t1.6.6b','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t1.6.6b','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t1.6.6b','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t1.6.6b','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t1.6.6b','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t1.6.6b','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t1.6.6b','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t2.7.7a','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t2.7.7a','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.7a','routerlifetime'))
        self.__config_setup1_1.set_intervalo(self.__config.get('t1.6.6b','intervalo'))
        self.__config_setup1_1.set_prefix_addr(self.__config.get('setup1-1_advertise','ia_pd_address'))
        self.__config_setup1_1.set_dhcp_t1(self.__config.get('t2.7.7a','dhcp_t1'))
        self.__config_setup1_1.set_dhcp_t2(self.__config.get('t2.7.7a','dhcp_t2'))
        self.__config_setup1_1.set_dhcp_preflft(self.__config.get('t2.7.7a','dhcp_preflft'))
        self.__config_setup1_1.set_dhcp_validlft(self.__config.get('t2.7.7a','dhcp_validlft'))
        self.__config_setup1_1.set_dhcp_plen(self.__config.get('t2.7.7a','dhcp_plen'))
   
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

    def icmp_rs_lan(self):
        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_ether_dst(self.__config.get('multicast','all_mac_routers'))
        self.__config_setup_lan.set_ipv6_dst(self.__config.get('general','all_routers_address'))
        self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
        self.__sendmsgs.send_icmp_rs(self.__config_setup_lan)

    def icmp_na_global_lan(self,pkt):
        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','global_wan_addr'))
        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_ether_dst(pkt[Ether].src)
        self.__config_setup_lan.set_ipv6_dst(pkt[IPv6].src)
        self.__config_setup_lan.set_tgt(self.__config.get('lan','global_wan_addr'))
        self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_mac_ceRouter(pkt[Ether].src)
        self.__sendmsgs.send_icmp_na_lan(self.__config_setup_lan)

    def icmp_na_local_lan(self,pkt):
        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_ether_dst(pkt[Ether].src)
        self.__config_setup_lan.set_ipv6_dst(pkt[IPv6].src)
        self.__config_setup_lan.set_tgt(self.__config.get('lan','lan_local_addr'))
        self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_mac_ceRouter(pkt[Ether].src)
        self.__sendmsgs.send_icmp_na_lan(self.__config_setup_lan)

    def echo_request_lan(self):
        #print('ENVIO REQUEST 1 LAN')

        mac_global = self.__config_setup_lan.get_global_mac_ceRouter()
        ip_global = self.__config_setup_lan.get_global_addr_ceRouter()
        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','global_wan_addr'))
        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_ether_dst(mac_global)
        self.__config_setup_lan.set_ipv6_dst(ip_global)
        self.__sendmsgs.send_echo_request_lan(self.__config_setup_lan)

    def ra_wan(self):
        self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
        self.__config_setup1_1.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
        self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','ra_address'))
        self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
        self.__sendmsgs.send_tr1_RA(self.__config_setup1_1)

    def run_Lan(self):

        @self.__app.route("/LAN",methods=['GET'])
        def envia_lan():
            return self.get_status_lan()
        #self.__config_setup_lan_.flags_partA()

        t_test = 0
        t_test1= 0
        sent_reconfigure = False
        time_over = False
        send_ra = False
        send_na_lan = False
        self.set_flags_lan()
        self.__config_setup_lan.set_setup_lan_start()
        temporizador_lan = 0
        test_max_time_lan = 250
        cache_lan = []
        while not self.__queue_lan.full():
            while self.__queue_lan.empty():
                if self.__config_setup1_1.get_setup1_1_OK():
                    time.sleep(1)
                    if temporizador_lan < test_max_time_lan:
                        temporizador_lan = temporizador_lan + 1
                    else:
                        self.set_status_lan('LAN: Reprovado. Timeout')
                        time.sleep(2)
                        self.set_status_lan('REPROVADO')
                        logging.info('LAN: Reprovado. Timeout')
                        #logging.info(routerlifetime)
                        self.__packet_sniffer_lan.stop()
                        self.__packet_sniffer_wan.stop()
                        return False
                    if temporizador_lan % 20 == 0:
                        logging.info('LAN: Tempo limite do teste: '+str(test_max_time_lan)+' segundos. Tempo: ' +str(temporizador_lan))
                        self.set_status_lan('LAN: Tempo limite do teste: '+str(test_max_time_lan)+' segundos. Tempo: ' +str(temporizador_lan))

                        if temporizador_lan % 5 ==0:
                            self.set_status_lan('LAN: Transmissão periódica de ICMP RS e DHCP information')
                            logging.info('LAN: Transmissão periódica de ICMP RS e DHCP information')
                            self.icmp_rs_lan()
                            self.dhcp_information_lan()

                        
                            if self.__config_setup_lan.get_ND_global_OK() and not self.__config_setup_lan.get_global_ping_OK():
                                self.set_status_lan('LAN: Transmissão Echo Request IP global do roteador')
                                logging.info('LAN: Transmissão Echo Request IP global do roteador')                                
                                self.echo_request_lan()

            pkt = self.__queue_lan.get()

            cache_lan.append(pkt)
            wrpcap("lan-2.7.7a.cap",cache_lan)

            if not self.__config_setup_lan.get_global_ping_OK():
                self.set_status_lan('LAN: Setup LAN em execução')
                logging.info('LAN: Setup LAN em execução')
                if not self.__config_setup_lan.get_disapproved():
                    self.__config_setup_lan.run_setup1_1(pkt)
                else:
                    logging.info('LAN: Reprovado Teste 2.7.7a - Falha em completar o setup 1.1')
                    self.set_status_lan('Reprovado Teste 2.7.7a - Falha em completar o setup 1.1')
                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True 
                    return False       
            else:
                logging.info('==========================================================================')
                logging.info('IMPORTANTE. ATIVE a ULA no roteador com o prefixo ' +  self.__config.get('t2.7.7a','prefix_ula'))
                logging.info('==========================================================================')
                time.sleep(30)

                if pkt.haslayer(ICMPv6ND_RA):
                    self.__routerlifetime_CeRouter = pkt[ICMPv6ND_RA].routerlifetime
                    if pkt.haslayer(ICMPv6NDOptPrefixInfo):
                        self.set_status_lan('LAN: RA recebido. Validando o Prefixo ULA')
                        logging.info('LAN: RA recebido. Validando o Prefixo ULA')
                        self.__prefixaddr_ula_CeRouter = pkt[ICMPv6NDOptPrefixInfo].prefix
                        if self.__prefixaddr_ula_CeRouter == self.__config.get('t2.7.7a','prefix_ula'):
                            logging.info(' Teste 2.7.7a: APROVADO: Recebido o prefix ULA previsto.')
                            self.set_status_lan('Teste 2.7.7a - APROVADO. Recebido o prefix ULA esperado.')
                            time.sleep(2)
                            self.set_status_lan('APROVADO') # Mensagem padrão para o frontEnd atualizar Status
                            self.__packet_sniffer_lan.stop()
                            self.__finish_wan = True
                            self.__fail_test = False 
                            return True
                        else:
                            self.set_status_lan('Teste 2.7.7a - REPROVADO. Recebido o prefix ULA incorreto.')
                            time.sleep(2)
                            self.set_status_lan('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                            logging.info('Teste 2.7.7a: REPROVADO. Recebido o prefix ULA incorreto.')
                            self.__packet_sniffer_lan.stop()
                            self.__finish_wan = True
                            self.__fail_test = True 
                            return False

                
    def run(self):
        @self.__app.route("/WAN",methods=['GET'])
        def enviawan():
            return self.get_status()

        self.__t_lan =  Thread(target=self.run_Lan,name='LAN_Thread')
        self.__packet_sniffer_lan = PacketSniffer('Test277a-LAN',self.__queue_lan,self,self.__config,self.__lan_device)        
        self.__packet_sniffer_wan = PacketSniffer('Test277a-WAN',self.__queue_wan,self,self.__config,self.__wan_device_tr1)

        self.__t_lan.start()
        self.__packet_sniffer_wan.start()
        self.__packet_sniffer_lan.start()

        self.set_flags()

        logging.info(self.__test_desc)

        logging.info('==========================================================================')
        logging.info('IMPORTANTE. Quando for Solicitado ative na ULA do roteador o prefixo: ' +  self.__config.get('t2.7.7a','prefix_ula'))
        logging.info('==========================================================================')
        
        time.sleep(10)

        t_test = 0
        sent_reconfigure = False
        time_over = False
        finish_wan = True
        cache_wan = []

        temporizador = 0
        test_max_time = 300

        self.__config_setup1_1.set_pd_prefixlen(self.__config.get('t2.7.7a','pd_prefixlen')) 
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.7a','routerlifetime')) 

        while not self.__queue_wan.full():
            while self.__queue_wan.empty():
                time.sleep(1)
                if temporizador < test_max_time:
                    temporizador = temporizador + 1
                else:
                    self.set_status('WAN: Reprovado. Timeout')
                    time.sleep(2)
                    self.set_status('REPROVADO')
                    logging.info('WAN: Reprovado. Timeout')
                    #logging.info(routerlifetime)
                    self.__packet_sniffer_lan.stop()
                    self.__packet_sniffer_wan.stop()
                    return False

                if temporizador % 20 == 0:
                    logging.info('WAN: Tempo limite do teste: '+str(test_max_time)+' segundos. Tempo: ' +str(temporizador))
                    self.set_status('WAN: Tempo limite do teste: '+str(test_max_time)+' segundos. Tempo: ' +str(temporizador))

                if temporizador % 15 ==0:
                    logging.info('WAN: Envio periódico de ICMP RA')
                    self.set_status('WAN: Envio periódico de ICMP RA')
                    self.ra_wan()

            pkt = self.__queue_wan.get()

            cache_wan.append(pkt)
            wrpcap("WAN-2.7.7a.cap",cache_wan)

            if not self.__config_setup1_1.get_setup1_1_OK():
                self.set_status('WAN: Setup 1.1 em execução.')
                logging.info('WAN: Setup 1.1 em execução.')
                if not self.__config_setup1_1.get_disapproved():
                    self.__config_setup1_1.run_setup1_1(pkt)
                else:
                    self.set_status('Reprovado Teste 2.7.7a - Falha em completar o Common Setup 1.1 da RFC')
                    logging.info('Reprovado Teste 2.7.7a - Falha em completar o Common Setup 1.1 da RFC')
                    self.__packet_sniffer_wan.stop() 
                    return False
            else:
                if self.__finish_wan:
                    self.__packet_sniffer_wan.stop()
                    if self.__fail_test:
                        return False
                    else:
                        return True
        self.__packet_sniffer_wan.stop()
        return False
     
        