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
import pdb
format = "%(asctime)s: %(message)s [%(levelname)s] (%(threadName)-9s)"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")

class PacketSniffer(Thread):
    def __init__(self,name,pass_queue,test,config,device):
        super(PacketSniffer,self).__init__()
        logging.info('Packet sniffer started')
        self.queue=pass_queue
        self.device_dict={}
        self.not_an_ap={}
        self.__test = test
        self.__interface = device
        self.__AsySnif = AsyncSniffer(iface=self.__interface,prn=self.PacketHandler)
        #sniff(iface=self.__interface,prn=self.PacketHandler)

        Thread(target=PacketSniffer.init(self),name=name)

    #def create(self):
        #self.__AsySnif = AsyncSniffer(iface=self.__interface,prn=self.PacketHandler)
        #sniff(iface=self.__interface,prn=self.PacketHandler)
        #self.__AsySnif.start()#

    def init(self):
        logging.info('AsyncSniffer start')
        self.__AsySnif.start()
    def stop(self):
        logging.info('AsyncSniffer stop')

        #pdb.set_trace()
        self.__AsySnif.stop()


    #def run(self):
        #print('run')
        #self.create()
        #Print (threading.currentThread().getName(), 'Run')
        #logging.info('Run')
        #sniff(iface=self.__interface,prn=self.PacketHandler)
        # if stop():
        #     break

    def put_queue(self,value):
        self.queue.put(value)

    def full_queue(self):
        return self.queue.full()

    def get_queue(self):
        return self.queue.get()

    def PacketHandler(self,pkt):
        if pkt.haslayer(IPv6):
            #print (threading.currentThread().getName(), 'Run')
            self.put_queue(pkt)


      