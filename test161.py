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


format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")
class Test161:

    def __init__(self,config,app):
        self.__app = app
        self.__queue = Queue()
        self.__config = config
        self.__interface = None
        self.__pkt = None
        self.__valid = False
        self.__result = None
        self.__taskDone = False
        self.__test_desc = self.__config.get('tests','1.6.1')
        self.msg = self.__config.get('tests','1.6.1')
        self.msg_lan = self.__config.get('tests','1.6.1')
        self.addr_ceRouter = None      

    def set_result(self, valor):
        self.__result = valor
        
    def get_result(self):
        return self.__result

    def set_task_done(self):
        self.__taskDone = True
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


    def run(self):
        @self.__app.route("/LAN",methods=['GET'])
        def envia_lan():

            return self.get_status_lan()

        @self.__app.route("/WAN",methods=['GET'])
        def enviawan():

            return self.get_status()

        self.__packet_sniffer_wan = PacketSniffer('test161',self.__queue,self,self.__config,self.__config.get('wan','device_wan_tr1'))
        t_test1 = 0
        t_test2 = 0

        cache_wan = []

        self.__packet_sniffer_wan.start()

        logging.info(self.__test_desc)

        logging.info(self.__queue.qsize())

        while self.__taskDone == False:

            pkt = self.__queue.get()
            cache_wan.append(pkt)
            wrpcap("wan-1.6.1.cap",cache_wan)
            

            if pkt.haslayer(ICMPv6ND_NS):
                if self.get_result() != False:
                    self.__valid = True
            elif pkt.haslayer(ICMPv6ND_RS) and self.__valid == False:
                self.set_result(False)
                self.set_task_done()
            if pkt.haslayer(ICMPv6ND_RS) and self.__valid == True:
                self.set_result(True)
                self.set_task_done()

 


        if self.get_result()== False:

            self.__packet_sniffer_wan.stop() 
            logging.info('Reprovado: Teste 1.6.1- ROTEADOR ENVIOU ICMP RS ANTES DO ENVIAR NS de seu endereço local')
            self.set_status('Reprovado: Teste 1.6.1- ROTEADOR ENVIOU ICMP RS ANTES DO ENVIAR NS de seu endereço local')
            time.sleep(2)
            self.set_status('REPROVADO') # Mensagem padrão para o frontEnd atualizar Status
            return False
        else:
            self.__packet_sniffer_wan.stop() 
            logging.info('APROVADO: Teste 1.6.1- ROTEADOR ENVIOU ICMP RS APOS TER ENVIADO NS de seu endereço local')
            self.set_status('APROVADO: Teste 1.6.1- ROTEADOR ENVIOU ICMP RS APOS TER ENVIADO NS de seu endereço local')
            time.sleep(2)
            self.set_status('APROVADO') # Mensagem padrão para o frontEnd atualizar Status
            return True

