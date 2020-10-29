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

class Test272b:

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
        self.__test_desc = self.__config.get('tests','2.7.2b')
        self.__t_lan = None
        self.msg = self.__config.get('tests','2.7.2b')
        self.msg_lan =self.__config.get('tests','2.7.2b')
        self.__config_setup_lan = ConfigSetup1_1_Lan(self.__config,self.__lan_device)

    def set_status_lan(self,v):
        self.msg_lan = v

    def get_status_lan(self):
        return self.msg_lan


    def set_status(self,v):
        self.msg = v

    def get_status(self):
        return self.msg




    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t2.7.2b','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t2.7.2b','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t2.7.2b','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t2.7.2b','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t2.7.2b','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t2.7.2b','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t2.7.2b','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t2.7.2b','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t2.7.2b','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.2b','routerlifetime'))
        self.__config_setup1_1.set_intervalo(self.__config.get('t2.7.2b','intervalo'))   

        self.__config_setup1_1.set_dhcp_t1(self.__config.get('t2.7.2b','dhcp_t1'))
        self.__config_setup1_1.set_dhcp_t2(self.__config.get('t2.7.2b','dhcp_t2'))
        self.__config_setup1_1.set_dhcp_preflft(self.__config.get('t2.7.2b','dhcp_preflft'))
        self.__config_setup1_1.set_dhcp_validlft(self.__config.get('t2.7.2b','dhcp_validlft'))
        self.__config_setup1_1.set_dhcp_plen(self.__config.get('t2.7.2b','dhcp_plen'))


    def set_flags_lan(self):
        self.__config_setup_lan.set_elapsetime(self.__config.get('solicitlan','elapsetime'))
        self.__config_setup_lan.set_xid(self.__config.get('solicitlan','xid'))
        self.__config_setup_lan.set_fdqn(self.__config.get('solicitlan','clientfqdn'))
        self.__config_setup_lan.set_vendor_class(self.__config.get('solicitlan','vendorclass'))

        self.__config_setup_lan.set_enterprise(self.__config.get('solicitlan','enterpriseid'))
        self.__config_setup_lan.set_client_duid(self.__config.get('solicitlan','duid'))
        self.__config_setup_lan.set_iaid(self.__config.get('solicitlan','iaid'))

        


    def run_Lan(self):
        @self.__app.route("/LAN",methods=['GET'])
        def envia_lan():
            return self.get_status_lan()
        #self.__config_setup_lan_.flags_partA()

        t_test = 0
        sent_reconfigure = False
        time_over = False
        self.set_flags_lan()
        cache_lan = []
        temporizador = 0
        test_max_time_lan = 300 
        
        while not self.__queue_lan.full():
            while self.__queue_lan.empty():
                time.sleep(1)
                
                if self.__config_setup1_1.get_setup1_1_OK():
                    self.__config_setup_lan.set_setup_lan_start()
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

                        return False
                    if temporizador % 20 == 0:

                        logging.info('LAN: Tempo limite do teste: '+str(test_max_time_lan)+' segundos. Tempo: ' +str(temporizador))
                        self.set_status_lan('LAN: Tempo limite do teste: '+str(test_max_time_lan)+' segundos. Tempo: ' +str(temporizador))

            pkt = self.__queue_lan.get()

            cache_lan.append(pkt)
            wrpcap("lan-2.7.2b.cap",cache_lan)

            if not self.__config_setup_lan.get_setup_OK():
                if not self.__config_setup_lan.get_disapproved():
                    self.__config_setup_lan.run_setup1_1(pkt)
                else:
                    logging.info('LAN: Reprovado Teste 2.7.5a - Falha em completar o setup 1.1')
                    self.set_status_lan('Reprovado Teste 2.7.5a - Falha em completar o setup 1.1')
                    time.sleep(2)
                    self.set_status_lan('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status

                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True 
                    self.__fail_test = True
                    return False   
            else:
                logging.info('LAN:Setup LAN  Concluido')
                self.set_status_lan('LAN:Setup LAN  Concluido')
                logging.info('Setup LAN  Concluido')
                #self.__packet_sniffer_wan.stop() 
                r_plen_CeRouter = self.__config_setup_lan.get_r_plen_CeRouter()
                r_rtlifetime_CeRouter = self.__config_setup_lan.get_r_lifetime_CeRouter()
                #validlifetime = self.__config_setup_lan.get_validlifetime_CeRouter()
                if r_plen_CeRouter == int(self.__config.get('t2.7.2b','pd_prefixlen')):
                    logging.info('Aprovado parcial: Teste 2.7.2b router Prefix len do CeRouter é igual designado em RA')
                    self.set_status_lan('Aprovado parcial: Teste 2.7.2b router Prefix len do CeRouter é igual designado em RA')

                    
                    #self.__packet_sniffer_lan.stop()
                    #return True
                else:
                    print('Valor esperado:')                     
                    print(self.__config.get('t2.7.2b','pd_prefixlen'))
                    print('Valor lido:')   
                    logging.info(r_plen_CeRouter)
                    logging.info('LAN: Reprovado Teste 2.7.2b router Prefix len do CeRouter NAO é igual designado em RA')
                    self.set_status_lan('LAN: Reprovado Teste 2.7.2b router Prefix len do CeRouter NAO é igual designado em RA')
                    time.sleep(2)
                    self.set_status_lan('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status

                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True 
                    self.__fail_test = True
                    return False   

                if r_rtlifetime_CeRouter < int(self.__config.get('t2.7.2b','routerlifetime')):
                    logging.info('Aprovado parcial: Teste 2.7.2b router Router Lifetime do CeRouter esta conforme valor designado em RA')
                    self.set_status_lan('Aprovado parcial: Teste 2.7.2b router Router Lifetime do CeRouter esta conforme valor designado em RA')

                    
                else:                     

                    logging.info(r_rtlifetime_CeRouter)
                    logging.info('LAN: Reprovado Teste 2.7.2b  router Router Lifetime do CeRouter NAO é igual designado em RA')
                    self.set_status_lan('LAN: Reprovado Teste 2.7.2b  router Router Lifetime do CeRouter NAO é igual designado em RA')
                    time.sleep(2)
                    self.set_status_lan('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status

                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True 
                    self.__fail_test = True
                    return False   

                logging.info('Aprovado Teste2.7.2b. Valor de Router life time e prefix Length conforme designados.')
                self.set_status_lan('Aprovado Teste2.7.2b. Valor de Router life time e prefix Length conforme designados. ')
                time.sleep(2)
                self.set_status_lan('APROVADO') # Mensagem padrão para o frontEnd atualizar Status
                
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
        
        self.__packet_sniffer_wan = PacketSniffer('Test271b-WAN',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()
        
        self.__packet_sniffer_lan = PacketSniffer('Test271b-LAN',self.__queue_lan,self,self.__config,self.__lan_device)
        test_lan = self.__packet_sniffer_lan.start()
        
        self.set_flags()
        logging.info(self.__test_desc)
        t_test = 0
        sent_reconfigure = False
        time_over = False
        cache_wan = []
        #time.sleep(11111)
        finish_wan = True
        self.__config_setup1_1.set_pd_prefixlen(self.__config.get('t2.7.2b','pd_prefixlen')) 
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.2b','routerlifetime')) 
        while not self.__queue_wan.full():
            while self.__queue_wan.empty():
                if t_test < 60:
                    time.sleep(1)
                    t_test = t_test + 1
                else:
                    time_over = True
            pkt = self.__queue_wan.get()
            cache_wan.append(pkt)
            wrpcap("WAN-2.7.2b.cap",cache_wan)
            if not self.__config_setup1_1.get_setup1_1_OK():
                logging.info('WAN: Setup 1.1 em execução')
                self.set_status('WAN: Setup 1.1 em execução') 
                if not self.__config_setup1_1.get_disapproved():
                    self.__config_setup1_1.run_setup1_1(pkt)
                else:
                    logging.info('Reprovado Teste 2.7.1b - Falha em completar o Common Setup 1.1 da RFC')
                    self.__packet_sniffer_wan.stop() 
                    return False

            else: 
                if not finish_wan:
                    self.__packet_sniffer_wan.stop()
                    finish_wan = True 
   
        self.__packet_sniffer_wan.stop()
        return False
     
        