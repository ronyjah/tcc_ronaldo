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


    def set_result(self, valor):
        self.__result = valor
        
    def get_result(self):
        return self.__result

    def set_task_done(self):
        self.__taskDone = True

    def run(self):

        logging.info('Passo1-create Packet sniffer')
        self.__packet_sniffer = PacketSniffer('test161',self.__queue,self,self.__config,self.__config.get('lan','lan_device'))

        logging.info('Passo3 - Start')
        self.__packet_sniffer.start()
        logging.info('Passo4-Started')
        logging.info(self.__test_desc)
        logging.info('self.__queue_size_inicio')
        logging.info(self.__queue.qsize())
        while self.__taskDone == False:

            pkt = self.__queue.get()
            self.__queue.task_done()

            if pkt.haslayer(ICMPv6ND_NS):
                if self.get_result() != False:
                    self.__valid = True
            elif pkt.haslayer(ICMPv6ND_RS) and self.__valid == False:
                self.set_result(False)

                logging.info('self.__queue_size_emptyfail')
                logging.info(self.__queue.qsize())
                if self.__queue.empty():
                    self.set_task_done()
            else:
                logging.info('self.__queue_size_emptysucess')
                logging.info(self.__queue.qsize())
                if self.__queue.empty():
                    self.set_task_done()


        if self.get_result()== False:

            logging.info('Passo3-t161run_sttop-theard fail')

            self.__packet_sniffer.stop()

            logging.info('self.__queue_size_fim')
            logging.info(self.__queue.qsize())

            return False
        else:
            logging.info('Passo4-t161run_sttop-theard success')

            self.__packet_sniffer.stop()

            logging.info('self.__queue_size_fim')
            logging.info(self.__queue.qsize())

            return True
