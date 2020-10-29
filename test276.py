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

class Test276:

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
        self.__test_desc = self.__config.get('tests','2.7.6')
        self.__t_lan = None
        self.__finish_wan = False
        self.__dhcp_renew_done = False
        self.msg = self.__config.get('tests','2.7.6')
        self.msg_lan =self.__config.get('tests','2.7.6')
        self.__config_setup_lan = ConfigSetup1_1_Lan(self.__config,self.__lan_device)



    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t2.7.6','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t2.7.6','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t2.7.6','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t2.7.6','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t2.7.6','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t2.7.6','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t2.7.6','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t2.7.6','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t2.7.6','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.6','routerlifetime'))
        self.__config_setup1_1.set_intervalo(self.__config.get('t1.6.6b','intervalo'))
        self.__config_setup1_1.set_prefix_addr(self.__config.get('setup1-1_advertise','ia_pd_address'))
        self.__config_setup1_1.set_dhcp_t1(self.__config.get('t2.7.6','dhcp_t1'))
        self.__config_setup1_1.set_dhcp_t2(self.__config.get('t2.7.6','dhcp_t2'))
        self.__config_setup1_1.set_dhcp_preflft(self.__config.get('t2.7.6','dhcp_preflft'))
        self.__config_setup1_1.set_dhcp_validlft(self.__config.get('t2.7.6','dhcp_validlft'))
        self.__config_setup1_1.set_dhcp_plen(self.__config.get('t2.7.6','dhcp_plen'))
   
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

    def rs_lan(self):

        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_ether_dst(self.__config.get('multicast','all_mac_routers'))
        self.__config_setup_lan.set_ipv6_dst(self.__config.get('general','all_routers_address'))
        self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
        self.__sendmsgs.send_icmp_rs(self.__config_setup_lan)
        
    def echo_request_lan(self):
        #print('ENVIO REQUEST 1 LAN')

        mac_global = self.__config_setup_lan.get_global_mac_ceRouter()
        ip_global = self.__config_setup_lan.get_global_addr_ceRouter()
        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','global_wan_addr'))
        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_ether_dst(mac_global)
        self.__config_setup_lan.set_ipv6_dst(ip_global)
        self.__sendmsgs.send_echo_request_lan(self.__config_setup_lan)

    def echo_request_lan_wrong_prefix(self):
        #print('ENVIO REQUEST 1 LAN')
        mac_global = self.__config_setup_lan.get_global_mac_ceRouter()
        ip_global = self.__config_setup_lan.get_global_addr_ceRouter()
        self.__config_setup_lan.set_ipv6_src(self.__config.get('t2.7.6','source_to_ping_tn1'))
        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_ether_dst(mac_global)
        self.__config_setup_lan.set_ipv6_dst(self.__config.get('wan','global_wan_addr'))
        self.__sendmsgs.send_echo_request_lan(self.__config_setup_lan)

    def icmp_na_wrong_prefix(self):
        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','global_wan_addr'))
        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_ether_dst(self.__config_setup_lan.get_global_mac_ceRouter())
        self.__config_setup_lan.set_ipv6_dst(self.__config_setup_lan.get_global_addr_ceRouter())
        self.__config_setup_lan.set_tgt(self.__config.get('t2.7.6','source_to_ping_tn1'))
        self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
        self.__sendmsgs.send_icmp_na_lan(self.__config_setup_lan)

    def dhcp_information_lan(self):
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
        logging.info('Thread da LAN inicio')
        t_test = 0
        t_test1= 0
        sent_reconfigure = False
        time_over = False
        send_ra = False
        send_na_lan = False
        self.set_flags_lan()
        self.__config_setup_lan.set_setup_lan_start()
        cache_lan = []
        temporizador_lan = 0
        test_max_time_lan = 300
        temporizador_ping = 0
        while not self.__queue_lan.full():
            while self.__queue_lan.empty():
                
                time.sleep(1)
                temporizador_ping = temporizador_ping + 1
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
                        self.__finish_wan = True 
                        self.__fail = True
                        return False
                    if temporizador_lan % 20 == 0:
                        logging.info('LAN: Tempo limite do teste: '+str(test_max_time_lan)+' segundos. Tempo: ' +str(temporizador_lan))
                        self.set_status_lan('LAN: Tempo limite do teste: '+str(test_max_time_lan)+' segundos. Tempo: ' +str(temporizador_lan))

                    if temporizador_lan % 5 ==0:
                        self.set_status_lan('LAN: Transmissão periódica de ICMP RS e DHCP information')
                        logging.info('LAN: Transmissão periódica de ICMP RS e DHCP information')
                        self.rs_lan()
                        self.dhcp_information_lan()
                        
                        if self.__config_setup_lan.get_ND_global_OK() and not self.__config_setup_lan.get_global_ping_OK():
                            self.set_status_lan('LAN: Transmissão Echo Request IP global do roteador')
                            logging.info('LAN: Transmissão Echo Request IP global do roteador')
                            self.echo_request_lan()

            pkt = self.__queue_lan.get()

            cache_lan.append(pkt)
            wrpcap("lan-2.7.6.cap",cache_lan)

            if not self.__config_setup_lan.get_global_ping_OK():

                if not self.__config_setup_lan.get_disapproved():
                    self.__config_setup_lan.run_setup1_1(pkt)
                else:
                    logging.info('LAN: Reprovado Teste 2.7.6 - Falha em completar o setup 1.1')
                    self.set_status_lan('Reprovado Teste 2.7.6 - Falha em completar o setup 1.1')
                    time.sleep(2)
                    self.set_status_lan('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status

                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True 
                    self.__fail = True
                    return False     
            else:
                temporizador_ping = temporizador_ping + 1

                if temporizador_ping % 5 ==0:

                    print(temporizador_ping)

                    self.set_status_lan('LAN: Transmissão Echo Request IP global  com prefix origem incorreto')
                    logging.info('LAN: Transmissão Echo Request IP global  com prefix origem incorreto')
                    self.echo_request_lan_wrong_prefix()

                if pkt[Ether].src == self.__config.get('lan','mac_address'):

                    continue

                if pkt.haslayer(ICMPv6ND_NS):
                    print('aqui3')
                    if pkt[ICMPv6ND_NS].tgt == self.__config.get('t2.7.6','source_to_ping_tn1'):

                        self.set_status_lan('LAN: Transmissão ICMP NA IP global com prefix origem  nao atribuido')
                        logging.info('LAN: Transmissão ICMP NA IP global com prefix origem  nao atribuido')
                        self.icmp_na_wrong_prefix()


                if pkt.haslayer(ICMPv6DestUnreach):
                    self.set_status('Teste 2.7.6- Pacote não foi encaminhado para WAN e CeRouter respondeu ao TN2 com Destino inalcançavel')
                    time.sleep(2)
                    self.set_status('APROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    logging.info('Teste 2.7.6- Pacote não foi encaminhado para WAN e CeRouter respondeu ao TN2 com Destino inalcançavel')

                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True
                    self.__fail_test = False 
                    return True







                if pkt.haslayer(ICMPv6EchoReply):
                    logging.info('LAN: Reprovado Teste 2.7.6 - Recebido Echo Reply de Echo Request com prefixo origem nao atribuido')
                    self.set_status_lan('LAN: Reprovado Teste 2.7.6 - Recebido Echo Reply de Echo Request com prefixo origem nao atribuido')
                    time.sleep(2)
                    self.set_status_lan('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status

                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True 
                    self.__fail = True
                    return False     




                
    def run(self):
        @self.__app.route("/WAN",methods=['GET'])
        def enviawan():
            return self.get_status()
        self.__t_lan =  Thread(target=self.run_Lan,name='LAN_Thread')
        self.__t_lan.start()
        
        self.__packet_sniffer_wan = PacketSniffer('Test273b-WAN',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()
        
        self.__packet_sniffer_lan = PacketSniffer('Test273b-LAN',self.__queue_lan,self,self.__config,self.__lan_device)
        test_lan = self.__packet_sniffer_lan.start()
        cache_wan = []
        self.set_flags()
        logging.info(self.__test_desc)
        t_test = 0
        sent_reconfigure = False
        time_over = False
        #time.sleep(11111)
        finish_wan = True
        test_max_time = 300
        temporizador = 0
        self.__config_setup1_1.set_pd_prefixlen(self.__config.get('t2.7.6','pd_prefixlen')) 
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.6','routerlifetime')) 
        #self.__config_setup1_1.active_DHCP_no_IA_PD()
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

                if temporizador < test_max_time:
                    if temporizador % 15 == 0:
                        self.ra_wan()

            pkt = self.__queue_wan.get()

            cache_wan.append(pkt)
            wrpcap("WAN-2.7.6.cap",cache_wan)
         
            if not self.__config_setup1_1.get_setup1_1_OK():
                self.set_status('WAN: Setup 1.1 em execução')
                logging.info('WAN: Setup 1.1 em execução')   
                if not self.__config_setup1_1.get_disapproved():
                    self.__config_setup1_1.run_setup1_1(pkt)
                else:
                    logging.info('LAN: Reprovado Teste 2.7.6 - Falha em completar o setup 1.1')
                    self.set_status_lan('Reprovado Teste 2.7.6 - Falha em completar o setup 1.1')
                    time.sleep(2)
                    self.set_status_lan('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True
                    self.__fail_test = True 
                    return False   

            else:
                if pkt.haslayer(ICMPv6EchoRequest):
                    self.__packet_sniffer_wan.stop()

                    self.set_status('Teste 2.7.6 - REPROVADO: Pacote ICMP Request com prefixo invalido foi encaminhado pelo roteador da LAN para WAN')
                    time.sleep(2)
                    self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    logging.info('Teste 2.7.6 - REPROVADO: Pacote ICMP Request com prefixo invalido foi encaminhado pelo roteador da LAN para WAN')

                    return False
                if self.__finish_wan: 
                    self.__packet_sniffer_wan.stop()
                    if self.__fail_test:
                        return False
                    else:
                        return True
        self.__packet_sniffer_wan.stop()
        return False
     
        