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

class Test277b:

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
        self.__test_desc = self.__config.get('tests','2.7.7b')
        self.__t_lan = None
        self.__finish_wan = False
        self.__dhcp_renew_done = False
        self.msg_lan = self.__config.get('tests','2.7.7b')
        self.msg = self.__config.get('tests','2.7.7b')
        self.__config_setup_lan = ConfigSetup1_1_Lan(self.__config,self.__lan_device)



    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t1.6.6b','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t1.6.6b','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t1.6.6b','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t1.6.6b','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t1.6.6b','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t1.6.6b','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t1.6.6b','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t2.7.7b','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t2.7.7b','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.7b','routerlifetime'))
        self.__config_setup1_1.set_intervalo(self.__config.get('t1.6.6b','intervalo'))
        self.__config_setup1_1.set_prefix_addr(self.__config.get('setup1-1_advertise','ia_pd_address'))
        self.__config_setup1_1.set_dhcp_t1(self.__config.get('t2.7.7b','dhcp_t1'))
        self.__config_setup1_1.set_dhcp_t2(self.__config.get('t2.7.7b','dhcp_t2'))
        self.__config_setup1_1.set_dhcp_preflft(self.__config.get('t2.7.7b','dhcp_preflft'))
        self.__config_setup1_1.set_dhcp_validlft(self.__config.get('t2.7.7b','dhcp_validlft'))
        self.__config_setup1_1.set_dhcp_plen(self.__config.get('t2.7.7b','dhcp_plen'))
   
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
        
    def run_Lan(self):

        t_test = 0
        t_test1= 0
        sent_reconfigure = False
        time_over = False
        send_ra = False
        send_na_lan = False
        self.set_flags_lan()
        cache_lan = []
        self.__config_setup_lan.set_setup_lan_start()

        @self.__app.route("/LAN",methods=['GET'])
        def envia_lan():
            return self.get_status_lan()

        while not self.__queue_lan.full():
            while self.__queue_lan.empty():

                time.sleep(1)
                
                if self.__config_setup1_1.get_setup1_1_OK():

                    if t_test < 80:
                        time.sleep(1)
                        t_test = t_test + 1
                        if t_test % 5 ==0:

                            self.set_status_lan('LAN: Transmissão periódica de ICMP RS e DHCP information')
                            self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
                            self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                            self.__config_setup_lan.set_ether_dst(self.__config.get('multicast','all_mac_routers'))
                            self.__config_setup_lan.set_ipv6_dst(self.__config.get('general','all_routers_address'))
                            self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
                            self.__sendmsgs.send_icmp_rs(self.__config_setup_lan)

                        
                            if self.__config_setup_lan.get_ND_global_OK() and not self.__config_setup_lan.get_global_ping_OK():
                                #print('ENVIO REQUEST 1 LAN')
                                self.set_status_lan('LAN: Transmissão Echo Request')
                                mac_global = self.__config_setup_lan.get_global_mac_ceRouter()
                                ip_global = self.__config_setup_lan.get_global_addr_ceRouter()
                                self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','global_wan_addr'))
                                self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                                self.__config_setup_lan.set_ether_dst(mac_global)
                                self.__config_setup_lan.set_ipv6_dst(ip_global)
                                self.__sendmsgs.send_echo_request_lan(self.__config_setup_lan)


                            #self.__config_setup_lan.set_setup_lan_start()
                            #print('#print ENVIO INFORMATION LAN')
                            self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
                            self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                            self.__config_setup_lan.set_ether_dst(self.__config.get('multicast','all_mac_routers'))
                            self.__config_setup_lan.set_ipv6_dst(self.__config.get('multicast','all_routers_addr'))
                            self.__config_setup_lan.set_xid(self.__config.get('informationlan','xid'))
                            #self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
                            self.__config_setup_lan.set_elapsetime(self.__config.get('informationlan','elapsetime'))
                            self.__config_setup_lan.set_vendor_class(self.__config.get('informationlan','vendorclass'))
                            self.__sendmsgs.send_dhcp_information(self.__config_setup_lan)
                    else: time_over = True

            pkt = self.__queue_lan.get()
            cache_lan.append(pkt)
            wrpcap("lan-2.7.7b.cap",cache_lan)
            if not self.__config_setup_lan.get_global_ping_OK():
                self.set_status('WAN: Setup 1.1 em execução')
                logging.info('WAN: Setup 1.1 em execução')

                #print('LOOP PRINCIPAL')
                if not self.__config_setup_lan.get_disapproved():
                    self.__config_setup_lan.run_setup1_1(pkt)
                else:
                    logging.info('LAN: Reprovado Teste 2.7.7b - Falha em completar o setup 1.1')
                    self.set_status_lan('Reprovado Teste 2.7.7b - Falha em completar o setup 1.1')
                    time.sleep(2)
                    self.set_status_lan('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status

                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True 
                    return False       
            else:
                if t_test1 < 60:
                    time.sleep(1)
                    t_test1 = t_test1 + 1
                    if pkt.haslayer(ICMPv6ND_RA):


                        self.__routerlifetime_CeRouter = pkt[ICMPv6ND_RA].routerlifetime
                        if pkt.haslayer(ICMPv6NDOptPrefixInfo):
                            self.set_status_lan('LAN: RA recebido. Verificando o Prefixo ULA')
                            logging.info('LAN: RA recebido. Verificando o Prefixo ULA')
                            self.__prefixaddr_ula_CeRouter = pkt[ICMPv6NDOptPrefixInfo].prefix
                            if self.__prefixaddr_ula_CeRouter == self.__config.get('t2.7.7b','prefix_ula'):
                                self.set_status('Teste 2.7.7b - APROVADO. Recebido o prefix ULA esperado.')
                                time.sleep(2)
                                self.set_status('APROVADO') # Mensagem padrão para o frontEnd atualizar Status
                                logging.info(' APROVADO Teste 2.7.7b: Recebido o prefix ULA esperado.')

                                self.__packet_sniffer_lan.stop()
                                self.__finish_wan = True
                                self.__fail_test = False 
                                return True  
                else:
                    self.set_status('WAN: Reprovado. CeRouter Enviou Prefix ULA durante o tempo de teste')
                    time.sleep(2)
                    self.set_status_lan('REPROVADO')
                    logging.info(' Teste2.7.7b: Prefix ULA Não recebido no tempo de teste')
                    #logging.info(routerlifetime)
                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True 
                    self.__fail_test = True
                    return False

                
    def run(self):
        self.set_status('Ative a ULA com prefixo: ' +  self.__config.get('t2.7.7b','prefix_ula') + ' . Reinicie o Roteador')

        @self.__app.route("/WAN",methods=['GET'])
        def enviawan():
            return self.get_status()
        
        self.set_flags()
        logging.info(self.__test_desc)
        logging.info('==========================================================================')
        logging.info('Ative a ULA com prefixo: ' +  self.__config.get('t2.7.7b','prefix_ula') + ' . Reinicie o Roteador') 
        logging.info('==========================================================================')
        
        time.sleep(10)
        self.__t_lan =  Thread(target=self.run_Lan,name='LAN_Thread')
        self.__t_lan.start()
        
        self.__packet_sniffer_wan = PacketSniffer('Test273b-WAN',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()
        
        self.__packet_sniffer_lan = PacketSniffer('Test273b-LAN',self.__queue_lan,self,self.__config,self.__lan_device)
        test_lan = self.__packet_sniffer_lan.start()
        cache_wan = []


        t_test = 0
        sent_reconfigure = False
        time_over = False
        cache_wan = []
        finish_wan = True
        self.__config_setup1_1.set_pd_prefixlen(self.__config.get('t2.7.7b','pd_prefixlen')) 
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.7b','routerlifetime')) 


        while not self.__queue_wan.full():
            while self.__queue_wan.empty():
                if t_test < 60:
                    time.sleep(1)
                    t_test = t_test + 1
                    if t_test % 15 ==0:
                        self.set_status('WAN: Envio periódico de RA a cada 15 seg durante 60 seg.')

                        self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
                        self.__config_setup1_1.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
                        self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','ra_address'))
                        self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
                        self.__sendmsgs.send_tr1_RA(self.__config_setup1_1)

                else:
                    time_over = True
            pkt = self.__queue_wan.get()
            cache_wan.append(pkt)
            wrpcap("WAN-2.7.7b.cap",cache_wan)
            if not self.__config_setup1_1.get_setup1_1_OK():
                self.set_status('WAN: Setup 1.1 em execução.')
                if not self.__config_setup1_1.get_disapproved():
                    self.__config_setup1_1.run_setup1_1(pkt)
                else:
                    self.set_status('WAN: Reprovado. CeRouter não completou setup 1.1')
                    time.sleep(2)
                    self.set_status('REPROVADO')
                    logging.info('Reprovado Teste 2.7.3a - Falha em completar o Common Setup 1.1 da RFC')
                    self.__packet_sniffer_wan.stop() 
                    return False

            else:
                if not self.__finish_wan:
                    pass
                else:
                    self.__packet_sniffer_wan.stop()
                    if self.__fail_test:
                        return False
                    else:
                        return True
        self.__packet_sniffer_wan.stop()
        return False
     
        