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

class Test273a:

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
        self.__test_desc = self.__config.get('tests','2.7.3a')
        self.__t_lan = None
        self.msg = self.__config.get('tests','2.7.3a')
        self.msg_lan =self.__config.get('tests','2.7.3a')
        self.__config_setup_lan = ConfigSetup1_1_Lan(self.__config,self.__lan_device)
        self.__finish_wan = None
        self.__fail_test = None


    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t1.6.6b','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t1.6.6b','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t1.6.6b','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t1.6.6b','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t1.6.6b','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t1.6.6b','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t1.6.6b','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t2.7.3a','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t2.7.3a','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.3a','routerlifetime'))
        self.__config_setup1_1.set_intervalo(self.__config.get('t1.6.6b','intervalo'))

        self.__config_setup1_1.set_dhcp_t1(self.__config.get('t2.7.3a','dhcp_t1'))
        self.__config_setup1_1.set_dhcp_t2(self.__config.get('t2.7.3a','dhcp_t2'))
        self.__config_setup1_1.set_dhcp_preflft(self.__config.get('t2.7.3a','dhcp_preflft'))
        self.__config_setup1_1.set_dhcp_validlft(self.__config.get('t2.7.3a','dhcp_validlft'))
        self.__config_setup1_1.set_dhcp_plen(self.__config.get('t2.7.3a','dhcp_plen'))
   
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

    def ra_wan(self):
        self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
        self.__config_setup1_1.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
        self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','ra_address'))
        self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
        self.__sendmsgs.send_tr1_RA(self.__config_setup1_1)

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
        logging.info('Thread da LAN')
        t_test = 0
        sent_reconfigure = False
        time_over = False
        self.set_flags_lan()
        cache_lan = []
        while not self.__queue_lan.full():
            while self.__queue_lan.empty():
                if t_test < 35:
                    time.sleep(1)

                    if self.__config_setup1_1.get_setup1_1_OK():
                        t_test = t_test + 1
                        logging.info('LAN: Fim do Setup1.1. Aguardando 35 segundos para enviar RS a LAN do Roteador Tempo: ' +str(t_test))
                        self.set_status_lan('LAN: Fim do Setup1.1. Aguardando 35 segundos para enviar RS ao Roteador . Tempo: ' +str(t_test))


                    #pkt = self.__queue_lan.get()
                else:
                    logging.info('LAN: . Enviando RS')
                    self.set_status_lan('LAN:. Enviando RS') 
                    self.__config_setup_lan.set_setup_lan_start() # nada funciona na LAN enquanto essa função nao executar
                    self.rs_lan()
           
            pkt = self.__queue_lan.get()
            cache_lan.append(pkt)
            wrpcap("lan-2.7.3a.cap",cache_lan)
            if not self.__config_setup_lan.get_setup_OK():
                if not self.__config_setup_lan.get_disapproved():
                    self.__config_setup_lan.run_setup1_1(pkt)
                else:
                    logging.info('LAN: Reprovado Teste 2.7.3a - Falha em completar o setup LAN')
                    self.set_status_lan('LAN: Reprovado Teste 2.7.3a - Falha em completar o setup LAN')
                    time.sleep(2)
                    self.set_status_lan('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True 
                    self.__fail_test = True
                    return False       
            else:
                logging.info('Setup LAN concluido. Verificando o valor de routerlifetime ')
                self.set_status_lan('Setup LAN concluido. o valor de  routerlifetime')
                routerlifetime = self.__config_setup_lan.get_routerlifetime_CeRouter()
                if routerlifetime == 0:
                    logging.info(' APROVADO  Teste 2.7.3b: routerlifetime OK. routerlifetime  igual a 0')
                    self.set_status_lan('APROVADO  Teste 2.7.3b: routerlifetime OK. routerlifetime  igual a 0')
                    time.sleep(2)
                    self.set_status_lan('APROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    
                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True
                    self.__fail_test = False 
                    return True 
                else:                     
                    logging.info(' REPROVADO  Teste 2.7.3a: routerlifetime. routerlifetime  acima de 0')
                    self.set_status_lan('REPROVADO  Teste 2.7.3a: routerlifetime. routerlifetime  acima de 0')
                    time.sleep(2)
                    self.set_status_lan('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True
                    self.__fail_test = False 
                    return True   

                
    def run(self):
        @self.__app.route("/WAN",methods=['GET'])
        def enviawan():
            return self.get_status()
        self.__t_lan =  Thread(target=self.run_Lan,name='LAN_Thread')
        self.__t_lan.start()
        
        self.__packet_sniffer_wan = PacketSniffer('Test273a-WAN',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()
        
        self.__packet_sniffer_lan = PacketSniffer('Test273a-LAN',self.__queue_lan,self,self.__config,self.__lan_device)
        self.__packet_sniffer_lan.start()
        
        self.set_flags()
        logging.info(self.__test_desc)
        t_test = 0
        sent_reconfigure = False
        time_over = False
        cache_wan = []
        finish_wan = True
        test_max_time = 300
        temporizador = 0 
        self.__config_setup1_1.set_pd_prefixlen(self.__config.get('t2.7.3a','pd_prefixlen')) 
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.3a','routerlifetime')) 
        self.__config_setup1_1.active_DHCP_no_IA_PD()
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
            wrpcap("WAN-2.7.3a.cap",cache_wan)
            if not self.__config_setup1_1.get_setup1_1_OK():
                logging.info('WAN: Setup 1.1 em execução')
                self.set_status('WAN: Setup 1.1 em execução') 
                if not self.__config_setup1_1.get_disapproved():
                    self.__config_setup1_1.run_setup1_1(pkt)
                else:
                    logging.info('WAN: Reprovado Teste 2.7.3a - Falha em completar o setup 1.1')
                    self.set_status('WAN: Reprovado Teste 2.7.3a - Falha em completar o setup 1.1')
                    time.sleep(2)
                    self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True
                    self.__fail_test = True 


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
     
        