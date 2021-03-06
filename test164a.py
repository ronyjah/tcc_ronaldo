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
import pdb
format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")

class Test164a:

    def __init__(self,config,app):
        self.__app = app
        self.__queue_wan = Queue()
        self.__queue_lan = Queue()
        self.__config = config
        self.__interface = None
        self.__pkt = None
        self.addr_ceRouter = None
        self.mac_ceRouter = None
        self.__local_addr_ceRouter =None
        self.__ND_local_OK = False
        self.__sendmsgs = SendMsgs(self.__config)
        self.__config_setup1_1 = ConfigSetup1_1(self.__config)
        self.__wan_device_tr1 = self.__config.get('wan','device_wan_tr1')
        self.__wan_mac_tr1 = self.__config.get('wan','wan_mac_tr1')
        self.__link_local_addr = self.__config.get('wan','link_local_addr')
        self.__all_nodes_addr = self.__config.get('multicast','all_nodes_addr')
        self.__test_desc = self.__config.get('tests','1.6.4')
        self.msg = self.__config.get('tests','1.6.4')
        self.msg_lan = self.__config.get('tests','1.6.4')
        

    def get_addr_ceRouter(self):
        return self.addr_ceRouter
    
    def get_mac_ceRouter(self):
        return self.mac_ceRouter

    def set_status_lan(self,v):
        self.msg_lan = v

    def get_status_lan(self):
        return self.msg_lan


    def set_status(self,v):
        self.msg = v

    def get_status(self):
        return self.msg

    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t1.6.4','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t1.6.4','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t1.6.4','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t1.6.4','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t1.6.4','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t1.6.4','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t1.6.4','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t1.6.4','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t1.6.4','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t1.6.4','routerlifetime'))
        self.__config_setup1_1.set_intervalo(self.__config.get('t1.6.4','intervalo'))    
        self.__config_setup1_1.set_pd_prefixlen(self.__config.get('t1.6.4','pd_prefixlen'))
    def run(self):

        @self.__app.route("/LAN",methods=['GET'])
        def envia_lan():

            return self.get_status_lan()

        @self.__app.route("/WAN",methods=['GET'])
        def enviawan():

            return self.get_status()

        self.__packet_sniffer_wan = PacketSniffer('test164',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()

        self.set_flags()         
        logging.info(self.__test_desc)
        t_test = 0
        sent_reconfigure = False
        time_over = False
        rs_ok = False
        send_ra = False
        send_ns =False
        send_ra2 = False
        send_ra_M_1 =False
        cache_wan = []
        scenario_OK = False
        while not self.__queue_wan.full():
            while self.__queue_wan.empty():
                if t_test < 120:
                    time.sleep(1)
                    t_test = t_test + 1
                    if t_test % 20 == 0:
                        logging.info('WAN: Tempo limite de teste 120 seg. Tempo atual: ' +str(t_test))
                        self.set_status('WAN: Tempo limite de teste 120 seg. Tempo atual:  ' +str(t_test))


                    if not self.__ND_local_OK:
                        continue
                    else:
                        if t_test % 5 == 0:
                            if not send_ns:

                                logging.info('WAN: TR1 Enviando ICMP NS')
                                self.set_status('WAN: TR1 Enviando ICMP NS')
                                print(self.__config_setup1_1.get_mac_ceRouter())
                                print(self.__config_setup1_1.get_local_addr_ceRouter())
                                #self.__sendmsgs.set_flags_common_setup(self.__config_setup1_1)
                                self.__config_setup1_1.set_ether_src(self.__config.get('wan','link_local_mac'))
                                self.__config_setup1_1.set_ether_dst(self.__config_setup1_1.get_mac_ceRouter())
                                self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','link_local_addr'))
                                self.__config_setup1_1.set_ipv6_dst(self.__config_setup1_1.get_local_addr_ceRouter())
                                self.__config_setup1_1.set_tgt(self.__config.get('wan','link_local_mac'))
                                
                                self.__sendmsgs.send_icmp_ns(self.__config_setup1_1)
                                print('Enviando NS_LOCAL')
                                continue

                else:
                    self.__packet_sniffer_wan.stop() 
                    logging.info('Reprovado: Teste 1.6.4- Cerouter com transmitiou Solicit dentro do tempo de Teste')
                    self.set_status('Reprovado: Teste 1.6.4- Cerouter com transmitiou Solicit dentro do tempo de Teste')
                    time.sleep(2)
                    self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                    
                    self.__packet_sniffer_wan.stop()
                    return False
            pkt = self.__queue_wan.get()
            #if not self.__ND_local_OK:
            cache_wan.append(pkt)
            wrpcap("wan-1.6.4.cap",cache_wan)
            
            if pkt.haslayer(ICMPv6ND_NS):
                print('NS')
                if pkt[ICMPv6ND_NS].tgt == '::':

                    continue
                if pkt[IPv6].src == self.__config.get('wan','link_local_addr'):
                    continue
                if pkt[IPv6].src == self.__config.get('wan','global_wan_addr'):
                    continue
                if pkt[IPv6].src == '::':
                    if pkt[ICMPv6ND_NS].tgt != '::':

                        self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)

                        self.__config_setup1_1.set_local_addr_ceRouter(pkt[ICMPv6ND_NS].tgt)

                        self.__ND_local_OK = True

                    if pkt[ICMPv6ND_NS].tgt != '::' and pkt[IPv6].src != '::':

                        pkt.show()

                    # self.addr_ceRouter = pkt[ICMPv6ND_NS].tgt
                    #     self.mac_ceRouter = pkt[Ether].src
                    #     self.__ND_local_OK = True

            if pkt.haslayer(ICMPv6ND_RS) and not self.__ND_local_OK:
                logging.info('WAN: Reprovado Teste 1.6.4a - Nao Recebeu ICMP NS antes do RS')
                self.set_status('WAN: Reprovado Teste 1.6.4a - Nao Recebeu ICMP NS antes do RS')
                time.sleep(2)
                self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                self.__packet_sniffer_wan.stop()
                return False  

            else:

                if not scenario_OK:
                    if not pkt.haslayer(ICMPv6ND_NA):
                        continue
                    else:
                        send_ns = True
                        scenario_OK = True

                if pkt.haslayer(DHCP6_Solicit) and send_ns and not send_ra_M_1 :       
                    if not send_ra_M_1:
                        logging.info('WAN: TR1 Enviando ICMP RA com Flag M para um ')
                        self.set_status('WAN: TR1 Enviando ICMP RA com Flag M para um') 
                        self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
                        self.__config_setup1_1.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
                        self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','link_local_addr'))
                        self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
                        self.__sendmsgs.send_tr1_RA(self.__config_setup1_1)
                        send_ra = True
                        send_ra_M_1 = True
                        while not self.__queue_wan.empty():
                            self.__queue_wan.get()
                            print('limpando raM1')

                        continue

                    #self.set_ether_dst(pkt[Ether].src)

                if send_ra_M_1 and not send_ra2:
                    if pkt.haslayer(DHCP6_Solicit):
                        
                            logging.info('WAN: TR1 Enviando ICMP RA com Flag M para zero ')
                            self.set_status('WAN: TR1 Enviando ICMP RA com Flag M para zero') 


                            self.__config_setup1_1.set_flag_M("0")
                            self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
                            self.__config_setup1_1.set_ether_dst(self.__config_setup1_1.get_mac_ceRouter())
                            self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','link_local_addr'))
                            self.__config_setup1_1.set_ipv6_dst(self.__config_setup1_1.get_local_addr_ceRouter())
                            self.__sendmsgs.send_tr1_RA(self.__config_setup1_1)
                            time.sleep(1)
                            while not self.__queue_wan.empty():
                                self.__queue_wan.get()
                                print('limpando')
                            send_ra2 = True
                            continue
                if send_ra2:
                    if pkt.haslayer(DHCP6_Solicit):
                            logging.info('WAN: Recebido DHCP Solicit. Verificando se contem ICMP IA_NA')
                            self.set_status('WAN: Recebido DHCP Solicit. Verificando se contem ICMP IA_NA')
                            if pkt.haslayer(DHCP6OptIA_NA):

                                logging.info('WAN: APROVADO Teste 1.6.4 - Roteador Enviou solicit com Option IA_NA')
                                self.set_status('WAN: APROVADO Teste 1.6.4 - Roteador Enviou solicit com Option IA_NA')
                                time.sleep(2)
                                self.set_status('APROVADO') # Mensagem padrão para o frontEnd atualizar Status
                                self.__packet_sniffer_wan.stop()

                                return True
                            else:

                                logging.info('WAN: Reprovado Teste 1.6.4 - Roteador Enviou solicit sem Option IA_NA')
                                self.set_status('WAN: Reprovado Teste 1.6.4 - Falha em completar o setup LAN')
                                time.sleep(2)
                                self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
                                self.__packet_sniffer_wan.stop()
                                return False  
    
        self.__packet_sniffer_wan.stop()
        return False
     
        