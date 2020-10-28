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
from flask import Flask,send_file,g,current_app,session

format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")

class Test277c:

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
        self.__test_desc = self.__config.get('tests','2.7.7c')
        self.__t_lan = None
        self.__finish_wan = False
        self.__dhcp_renew_done = False
        self.msg = self.__config.get('tests','2.7.7c')

        self.msg_lan =self.__config.get('tests','2.7.7c')
        self.__config_setup_lan = ConfigSetup1_1_Lan(self.__config,self.__lan_device)



    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t1.6.6b','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t1.6.6b','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t1.6.6b','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t1.6.6b','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t1.6.6b','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t1.6.6b','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t1.6.6b','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t2.7.7c','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t2.7.7c','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.7c','routerlifetime'))
        self.__config_setup1_1.set_intervalo(self.__config.get('t1.6.6b','intervalo'))
        self.__config_setup1_1.set_prefix_addr(self.__config.get('setup1-1_advertise','ia_pd_address'))
        self.__config_setup1_1.set_dhcp_t1(self.__config.get('t2.7.7c','dhcp_t1'))
        self.__config_setup1_1.set_dhcp_t2(self.__config.get('t2.7.7c','dhcp_t2'))
        self.__config_setup1_1.set_dhcp_preflft(self.__config.get('t2.7.7c','dhcp_preflft'))
        self.__config_setup1_1.set_dhcp_validlft(self.__config.get('t2.7.7c','dhcp_validlft'))
        self.__config_setup1_1.set_dhcp_plen(self.__config.get('t2.7.7c','dhcp_plen'))
   
    def set_flags_lan(self):
        self.__config_setup_lan.set_elapsetime(self.__config.get('solicitlan','elapsetime'))
        self.__config_setup_lan.set_xid(self.__config.get('solicitlan','xid'))
        self.__config_setup_lan.set_fdqn(self.__config.get('solicitlan','clientfqdn'))
        self.__config_setup_lan.set_vendor_class(self.__config.get('solicitlan','vendorclass'))

        self.__config_setup_lan.set_enterprise(self.__config.get('solicitlan','enterpriseid'))
        self.__config_setup_lan.set_client_duid(self.__config.get('solicitlan','duid'))
        self.__config_setup_lan.set_iaid(self.__config.get('solicitlan','iaid'))
    def set_status(self,v):
        self.msg = v

    def get_status(self):
        return self.msg

    def set_status_lan(self,v):
        self.msg_lan = v

    def get_status_lan(self):
        return self.msg_lan   

        
    def run_Lan(self):
        #self.__config_setup_lan_.flags_partA()
        logging.info('Thread da LAN inicio')
        t_test = 0
        t_test1= 0
        sent_reconfigure = False
        time_over = False
        send_ra = False
        send_na_lan = False
        cache_lan = []
        self.set_flags_lan()
        self.__config_setup_lan.set_setup_lan_start()

        @self.__app.route("/LAN",methods=['GET'])
        def envia_lan():
            return self.get_status_lan()

        while not self.__queue_lan.full():
            while self.__queue_lan.empty():
                if t_test1 < 80:
                    time.sleep(1)
                    t_test1 = t_test1 + 1
                    if t_test1 % 5 == 0:
                        logging.info('LAN: Enviando  RS periódico: tempo limite: '+str(80)+' segundos. Tempo atual: ' +str(t_test1))
                        self.set_status_lan('LAN: Enviando  RS periódico: tempo limite: '+str(80)+' segundos. Tempo atual: ' +str(t_test1))
                        self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
                        self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                        self.__config_setup_lan.set_ether_dst(self.__config.get('multicast','all_mac_routers'))
                        self.__config_setup_lan.set_ipv6_dst(self.__config.get('general','all_routers_address'))
                        self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
                        self.__sendmsgs.send_icmp_rs(self.__config_setup_lan)
                else:
                    self.set_status_lan('Reprovado Teste 2.7.7c - Prefix ULA Não recebido durante o tempo de teste')
                    time.sleep(2)
                    self.set_status_lan('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    logging.info(' Reprovado Teste2.7.7c: Prefix ULA Não recebido durante o tempo de teste')
                    #logging.info(routerlifetime)
                    self.__finish_wan = True 
                    self.__fail_test = True
                    return False
            pkt = self.__queue_lan.get()
            cache_lan.append(pkt)
            wrpcap("lan-2.7.7c.cap",cache_lan)
            if pkt.haslayer(ICMPv6ND_RA):
                self.set_status_lan('LAN: RA recebido. Verificando o Prefixo ULA')
                logging.info('LAN: RA recebido. Verificando o Prefixo ULA')

                self.__routerlifetime_CeRouter = pkt[ICMPv6ND_RA].routerlifetime
                if pkt.haslayer(ICMPv6NDOptPrefixInfo):
                    self.__prefixaddr_ula_CeRouter = pkt[ICMPv6NDOptPrefixInfo].prefix
                    if self.__prefixaddr_ula_CeRouter == self.__config.get('t2.7.7c','prefix_ula'):

                        self.set_status('Teste 2.7.7c - APROVADO. Recebido o prefix ULA esperado.')
                        time.sleep(2)
                        self.set_status('APROVADO') # Mensagem padrão para o frontEnd atualizar Status
                        logging.info(' APROVADO Teste 2.7.7c: Recebido o prefix ULA esperado.')
                        self.__finish_wan = True
                        self.__fail_test = False 
                        return True  

                
    def run(self):
        self.set_status('Ative a ULA com prefixo: ' +  self.__config.get('t2.7.7c','prefix_ula') + ' Reinicie o Roteador')

        @self.__app.route("/WAN",methods=['GET'])
        def enviawan():
            return self.get_status()
        cache_wan = []
        self.set_flags()
        logging.info(self.__test_desc)
        logging.info('==================================================================================')
        logging.info('Ative a ULA com prefixo: ' +  self.__config.get('t2.7.7c','prefix_ula') + ' Reinicie o Roteador') 
        logging.info('==================================================================================')
        
        time.sleep(10)
        self.__t_lan =  Thread(target=self.run_Lan,name='LAN_Thread')
        self.__t_lan.start()
        
        self.__packet_sniffer_wan = PacketSniffer('Test273b-WAN',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()
        
        self.__packet_sniffer_lan = PacketSniffer('Test277c-LAN',self.__queue_lan,self,self.__config,self.__lan_device)
        test_lan = self.__packet_sniffer_lan.start()
        cache_wan = []


        t_test = 0


        while not self.__queue_wan.full():
            if self.__queue_wan.empty():
                self.set_status('Temporizador do teste: 300 segundos')
                if t_test <= 300:
                    time.sleep(1)
                    t_test = t_test + 1
                else:
                    self.__packet_sniffer_wan.stop() 
                    self.__packet_sniffer_lan.stop()
                    self.set_status('Timeout')
                    logging.info('WAN: Timeout')
                    time.sleep(2)
                    self.set_status('REPROVADO')
                    time_over = True 
            else:

                pkt = self.__queue_wan.get()
                cache_wan.append(pkt)
                wrpcap("WAN-2.7.7c.cap",cache_wan)
                if not self.__finish_wan:
                    pass 
                else:
                    self.__packet_sniffer_wan.stop() 
                    self.__packet_sniffer_lan.stop()
                    time_over = True 
    
                    if self.__fail_test:
                        return False
                    else:
                        return True
        self.__packet_sniffer_wan.stop()
        return False
     
        