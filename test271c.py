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

class Test271c:

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
        self.__test_desc = self.__config.get('tests','2.7.1c')
        self.__t_lan = None
        self.__finish_wan = False
        self.__fail_test = False
        self.msg = self.__config.get('tests','2.7.1c')
        self.msg_lan =self.__config.get('tests','2.7.1c')
        self.__config_setup_lan = ConfigSetup1_1_Lan(self.__config,self.__lan_device)



    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t2.7.1c','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t2.7.1c','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t2.7.1c','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t2.7.1c','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t2.7.1c','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t2.7.1c','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t2.7.1c','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t2.7.1c','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t2.7.1c','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.1c','routerlifetime'))
        self.__config_setup1_1.set_intervalo(self.__config.get('t2.7.1c','intervalo'))   
  
        self.__config_setup1_1.set_dhcp_t1(self.__config.get('t2.7.1c','dhcp_t1'))
        self.__config_setup1_1.set_dhcp_t2(self.__config.get('t2.7.1c','dhcp_t2'))
        self.__config_setup1_1.set_dhcp_preflft(self.__config.get('t2.7.1c','dhcp_preflft'))
        self.__config_setup1_1.set_dhcp_validlft(self.__config.get('t2.7.1c','dhcp_validlft'))
        self.__config_setup1_1.set_dhcp_plen(self.__config.get('t2.7.1c','dhcp_plen'))


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

    def rs_lan(self):

        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
        self.__config_setup_lan.set_ether_dst(self.__config.get('multicast','all_mac_routers'))
        self.__config_setup_lan.set_ipv6_dst(self.__config.get('general','all_routers_address'))
        self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
        self.__sendmsgs.send_icmp_rs(self.__config_setup_lan)

    def run_Lan(self):

        @self.__app.route("/LAN",methods=['GET'])
        def envia_lan():
            return self.get_status_lan()
        #self.__config_setup_lan_.flags_partA()
        
        t_test = 0
        sent_reconfigure = False
        time_over = False
        cache_wan = []
        self.set_flags_lan()
        cache_lan = []
        temporizador = 0
        test_max_time_lan = 300
        self.__config_setup_lan.set_setup_lan_start()
        while not self.__queue_lan.full():
            while self.__queue_lan.empty():
                time.sleep(1)
                if self.__config_setup1_1.get_setup1_1_OK():

                    if temporizador < test_max_time_lan:
                        temporizador = temporizador + 1
                    else:
                        self.set_status_lan('LAN: Reprovado. Timeout')
                        time.sleep(2)
                        self.set_status_lan('REPROVADO')
                        logging.info('LAN: Reprovado. Timeout')
                        #logging.info(routerlifetime)
                        self.__finish_wan = True 
                        self.__fail_test = True
                        self.__packet_sniffer_lan.stop()

                    if temporizador % 20 == 0:


                        logging.info('LAN: Tempo limite do teste: '+str(test_max_time_lan)+' segundos. Tempo: ' +str(temporizador))
                        self.set_status_lan('LAN: Tempo limite do teste: '+str(test_max_time_lan)+' segundos. Tempo: ' +str(temporizador))
                    if temporizador % 8 ==0:
                        self.set_status_lan('LAN: Transmissão periódica de ICMP RS ')
                        logging.info('LAN: Transmissão periódica de ICMP RS ')
                        self.rs_lan()
            pkt = self.__queue_lan.get()

            cache_lan.append(pkt)
            wrpcap("lan-2.7.1c.cap",cache_lan)
            
            if self.__config_setup1_1.get_setup1_1_OK():
                if pkt.haslayer(ICMPv6ND_RA):
                    if pkt.haslayer(ICMPv6NDOptPrefixInfo):
                        logging.info('LAN: Reprovado Teste 2.7.1c: Roteador transmitiu na LAN RA com IA_PD sendo que recebeu Validtime inferior ao preferedtime')
                        self.set_status_lan('LAN: Reprovado Teste 2.7.1c: Roteador transmitiu na RA com LAN IA_PD sendo que recebeu Validtime inferior ao preferedtime')
                        time.sleep(2)
                        self.set_status_lan('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                        self.__packet_sniffer_lan.stop()
                        self.__finish_wan = True 
                        self.__fail_test = True
                        return False   
                    if pkt.haslayer(ICMPv6NDOptRouteInfo):
                        prefix_route =pkt[ICMPv6NDOptRouteInfo].prefix
                        plen_route = pkt[ICMPv6NDOptRouteInfo].plen
                        if(prefix_route == '::') and  (plen_route == 0):
                            logging.info('Aprovado Teste2.7.1c. Roteador nao enviou na LAN RA Prefix info apos o roteador receber na WAN Validtime menor que prefered time.')
                            self.set_status_lan('Aprovado Teste2.7.1c. Roteador nao enviou na LAN RA recebeu Prefix info apos o roteador na WAN receber Validtime menor que prefered time.')
                            time.sleep(2)
                            self.set_status_lan('APROVADO') # Mensagem padrão para o frontEnd atualizar Status
                            self.__packet_sniffer_lan.stop()
                            self.__finish_wan = True
                            self.__fail_test = False 
                            return True       

            # print('pre setup lan')
            # print(self.__config_setup_lan.get_setup_OK())
            # if not self.__config_setup_lan.get_setup_OK():
            #     print('setup lan')
            #     if not self.__config_setup_lan.get_disapproved():
            #         self.__config_setup_lan.run_setup1_1(pkt)
            #     else:
            #         logging.info('LAN: Reprovado Teste 2.7.1c - Falha em completar o setup LAN')
            #         self.set_status_lan('Reprovado Teste 2.7.1c - Falha em completar o setup LAN')
            #         time.sleep(2)
            #         self.set_status_lan('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
            #         self.__packet_sniffer_lan.stop()
            #         self.__finish_wan = True 
            #         self.__fail_test = True
            #         return False  
            # else:
            #     print('Pos setup lan')
            #     logging.info('LAN:Setup LAN  Concluido')
            #     self.set_status_lan('LAN:Setup LAN  Concluido')
            #     #self.__packet_sniffer_wan.stop() 
            #     prefrix_pd = self.__config_setup_lan.get_prefixlen_CeRouter()
            #     preferredlifetime = self.__config_setup_lan.get_preferredlifetime_CeRouter()
            #     validlifetime = self.__config_setup_lan.get_validlifetime_CeRouter()

            #     if prefrix_pd == 64:
            #         logging.info('Aprovado parcial: Teste 2.7.1c router PD length é igual a 64')
            #         self.set_status_lan('Aprovado parcial: Teste 2.7.1c router PD length é igual a 64')
            #     else:                     
            #         logging.info('Valor esperado: 64')
            #         logging.info('Valor lido:')
            #         logging.info(prefrix_pd)
            #         logging.info('LAN: REPROVADO Teste 2.7.1c router IA_PD length é igual a 64')
            #         self.set_status_lan('LAN: Reprovado Teste 2.7.1c router IA_PD length IA_PD length 64')
            #         time.sleep(2)
            #         self.set_status_lan('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
            #         self.__packet_sniffer_lan.stop()
            #         self.__finish_wan = True 
            #         self.__fail_test = True
            #         return False   

            #     if preferredlifetime < int(self.__config.get('t2.7.1c','preferredlifetime')):
            #         logging.info(' Teste 2.7.1c: preferredlifetime OK. preferredlifetime dentro do especificado no RA')
            #         self.set_status_lan('Aprovado parcial: Teste 2.7.1c:  preferredlifetime dentro do especificado no RA')
            #     else:                     
            #         logging.info(' Teste 2.7.1c: Reprovado. preferredlifetime acima do especificado no RA')
            #         logging.info('Valor lido:')
            #         logging.info(preferredlifetime)
            #         self.set_status_lan('LAN:  Teste 2.7.1c: Reprovado. preferredlifetime acima do especificado no RA')
            #         time.sleep(2)
            #         self.set_status_lan('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
            #         self.__packet_sniffer_lan.stop()
            #         self.__finish_wan = True 
            #         self.__fail_test = True
            #         return False   

            #     if validlifetime < int(self.__config.get('t2.7.1c','validlifetime')):
            #         logging.info('Teste 2.7.1c: validlifetime OK. validlifetime dentro do especificado no RA')
            #         self.set_status_lan('Aprovado parcial: Teste 2.7.1c:  validlifetime dentro do especificado no RA')

            #         #self.__packet_sniffer_lan.stop()
            #         #return True
            #     else:       
            
            #         logging.info('LAN:  Teste 2.7.1c: Reprovado. validlifetime acima do especificado no RA:')
            #         logging.info(validlifetime)
            #         self.set_status_lan('LAN:  Teste 2.7.1c: Reprovado. validlifetime acima do especificado no RA')
            #         time.sleep(2)
            #         self.set_status_lan('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
            #         self.__packet_sniffer_lan.stop()
            #         self.__finish_wan = True 
            #         self.__fail_test = True
            #         return False   
            #         logging.info('LAN: Reprovado Teste 2.7.2a  router Router Lifetime do CeRouter NAO é igual designado em RA')
            #         self.set_status_lan('LAN: Reprovado Teste 2.7.2a  router Router Lifetime do CeRouter NAO é igual designado em RA')
            #         time.sleep(2)
            #         self.set_status_lan('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status

            #         self.__packet_sniffer_lan.stop()
            #         self.__finish_wan = True 
            #         self.__fail_test = True
            #         return False   




    def ra_wan(self):
        self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
        self.__config_setup1_1.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
        self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','ra_address'))
        self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
        self.__sendmsgs.send_tr1_RA(self.__config_setup1_1)

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
        
        self.set_flags()
        logging.info(self.__test_desc)
        t_test = 0
        sent_reconfigure = False
        time_over = False
        #time.sleep(11111)
        finish_wan = True
        self.__config_setup1_1.set_pd_prefixlen(self.__config.get('t2.7.1b','pd_prefixlen')) 
        test_max_time = 300
        temporizador = 0
        cache_wan = []
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

                if temporizador % 10 ==0:
                    logging.info('WAN: Envio de RA periódico')
                    self.set_status('WAN: Envio de RA periódico')
                    self.ra_wan()                  

            pkt = self.__queue_wan.get()

            cache_wan.append(pkt)
            wrpcap("wan-2.7.1c.cap",cache_wan)

            if not self.__config_setup1_1.get_setup1_1_OK():
                logging.info('WAN: Setup 1.1 em execução')
                self.set_status('WAN: Setup 1.1 em execução') 
                if not self.__config_setup1_1.get_disapproved():
                    self.__config_setup1_1.run_setup1_1(pkt)
                else:
                    logging.info('WAN: Reprovado Teste 2.7.1c - Falha em completar o setup 1.1')
                    self.set_status('WAN: Reprovado Teste 2.7.1c - Falha em completar o setup 1.1')
                    time.sleep(2)
                    self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True
                    self.__fail_test = True
                    return False 

            else: 
                logging.info('WAN: Setup 1.1 Concluido')
                self.set_status('WAN: Setup 1.1 Concluido') 
                if self.__finish_wan: 
                    self.__packet_sniffer_wan.stop()
                    if self.__fail_test:
                        return False
                    else:
                        return True
        self.__packet_sniffer_wan.stop()
        return False
     
        