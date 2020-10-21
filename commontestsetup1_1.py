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


# - Seleciona a interface
# - recebe thread de captura das mensagens já iniciada na main
# - inicia a captura
# - recebe o pacote e armazena numa lista
# - analisa o pacote recebido e armazenado na lista
# - 

format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")

class CommonTestSetup1_1:

    def __init__(self,config):
        #self.self_testing = self
        self.__queue_wan = Queue()
        self.__queue_lan = Queue()
        logging.info('self.__queue_size_inicio162')
        logging.info(self.__queue_wan.qsize())
        self.__config = config
        self.__interface = None
        self.__pkt = None
        self.__valid = False
        self.__result = None
        self.__device_lan_tn1 = None
        self.__lan_mac_tn1 = None
        self.__ceRouter_mac_addr = None
        self.__flag_M = 1
        self.__flag_O = 0
        self.__flag_chlim = 64
        self.__flag_L = 1
        self.__flag_A = 0
        self.__flag_R = 0
        self.__validlifetime = 600
        self.__preferredlifetime = 600
        self.__interval = 1
        self.__routerlifetime =200
        self.__wan_device_tr1 = self.__config.get('wan','device_wan_tr1')
        self.__wan_mac_tr1 = self.__config.get('wan','wan_mac_tr1')
        self.__link_local_addr = self.__config.get('wan','link_local_addr')
        self.__all_nodes_addr = self.__config.get('multicast','all_nodes_addr')
        self.__global_addr = self.__config.get('wan','global_addr')
        self.__test_desc = self.__config.get('tests','common1-1')


    def set_flags_common_setup(self,test_flags):
        self.__flag_M = test_flags.get_flag_M()
        self.__flag_O = test_flags.get_flag_O()
        self.__flag_chlim = test_flags.get_flag_chlim()
        self.__flag_L = test_flags.get_flag_L()
        self.__flag_A = test_flags.get_flag_A()
        self.__flag_R = test_flags.get_flag_R()
        self.__validlifetime = test_flags.get_validlifetime()
        self.__preferredlifetime = test_flags.get_preferredlifetime()
        self.__routerlifetime = test_flags.get_routerlifetime()
        self.__intervalo = test_flags.get_interval()

    def ether(self,test=None):
        print('etheraddres')
        print (test.get_ether_dst())
        return Ether(src= test.get_ether_src() if test else self.__wan_mac_tr1,\
                dst = test.get_ether_dst() if test else None)

    def ipv6(self,test=None):
        print('ipv6addres')
        print (test.get_ipv6_dst())
        return IPv6(src=test.get_ipv6_src() if test else self.__link_local_addr,\
                    dst= test.get_ipv6_dst() if test else self.__all_nodes_addr)
    
    def icmpv6_ra(self,test=None):
        return ICMPv6ND_RA(M=self.__flag_M,\
                            O=self.__flag_O,\
                            routerlifetime=self.__routerlifetime,\
                            chlim=self.__flag_chlim)

    def icmpv6_pd(self,Test=None):
        return ICMPv6NDOptPrefixInfo(L=self.__flag_L,\
                                        A=self.__flag_A,\
                                        R=self.__flag_R,\
                                        validlifetime=self.__validlifetime,\
                                        preferredlifetime=self.__preferredlifetime,\
                                        prefix=self.__global_addr)

    def icmpv6_ns(self,test=None):
        return ICMPv6ND_NS(tgt=test.get_tgt())

    def udp(self):
        return UDP()

    def dhcp(self):
        return DHCP6()

    def dhcp_advertise(self,test=None):
        return DHCP6_Advertise(trid=test.get_xid())
    
    def dhcp_client_id(self,test=None):
        return DHCP6OptClientId(duid=test.get_client_duid())

    def dhcp_server_id(self,test=None):
        return DHCP6OptServerId(duid=test.get_server_duid())

    def opt_ia_na(self,test=None):
        # optcode    : ShortEnumField                      = (25)
        # optlen     : FieldLenField                       = (None)
        # iaid       : XIntField                           = (None)
        # T1         : IntField                            = (None)
        # T2         : IntField                            = (None)
        # iapdopt    : PacketListField                     = ([])
        return DHCP6OptIA_NA(iaid = test.get_iaid(),\
                            T1 = int(self.__config.get('setup1-1_advertise','t1')),\
                            T2 = int(self.__config.get('setup1-1_advertise','t2')),\
                            ianaopts=DHCP6OptIAAddress(addr=self.__config.get('setup1-1_advertise','ia_na_address'),\
                                                        preflft=int(self.__config.get('setup1-1_advertise','ia_na_pref_lifetime')),\
                                                        validlft=int(self.__config.get('setup1-1_advertise','ia_na_validtime'))))
    
    def opt_ia_pd(self,test=None):


#         optcode    : ShortEnumField                      = (26)
# optlen     : FieldLenField                       = (None)
# preflft    : IntEnumField                        = (0)
# validlft   : IntEnumField                        = (0)
# plen       : ByteField                           = (48)
# prefix     : IP6Field                            = ('2001:db8::')
# iaprefopts : PacketListField                     = ([])
        return DHCP6OptIA_PD(iaid =test.get_iaid(),\
                            T1 = int(self.__config.get('setup1-1_advertise','t1')),\
                            T2 = int(self.__config.get('setup1-1_advertise','t2')),\
                            iapdopt=DHCP6OptIAPrefix(prefix = self.__config.get('setup1-1_advertise','ia_pd_address'),\
                                                        preflft = int(self.__config.get('setup1-1_advertise','ia_pd_pref_lifetime')),\
                                                        validlft = int(self.__config.get('setup1-1_advertise','ia_pd_validtime')),\
                                                        plen= int(self.__config.get('setup1-1_advertise','ia_pd_pref_len'))))

    def opt_dns_server(self):
        return DHCP6OptDNSServers(dnsservers=[self.__config.get('setup1-1_advertise','dns_rec_name_server')])

    def opt_dns_domain(self):
        #dnsdomains : DomainNameListField                 = ([])
        return DHCP6OptDNSDomains(dnsdomains=[self.__config.get('setup1-1_advertise','domain_search')])

    def dhcp_reply(self):
        return DHCP6_Reply()

    def echo_request(self):
        return ICMPv6EchoRequest()

    def dhcp_reconfigure(self,test):
        return DHCP6OptReconfMsg(msgtype=int(test.get_dhcp_reconf_type()))
    
    def dhcp_auth(self,test=None):
        # optcode    : ShortEnumField                      = (11)
        # optlen     : FieldLenField                       = (None)
        # proto      : ByteEnumField                       = (3)
        # alg        : ByteEnumField                       = (1)
        # rdm        : ByteEnumField                       = (0)
        # replay     : StrFixedLenField                    = ('\x00\x00\x00\x00\x00\x00\x00\x00')
        # authinfo   : StrLenField   
        return DHCP6OptAuth(replay=self.__config.get('t1.6.3','replay'),\
                            authinfo = self.__config.get('t1.6.3','authinfo'))
        



    def send_tr1_RA(self,fields=None):
        # tr1_et = Ether(src=self.__wan_mac_tr1)
        # tr1_ip = IPv6(src=self.__link_local_addr,\
        #               dst=self.__all_nodes_addr)
        # tr1_rs = ICMPv6ND_RA(M=self.__flag_M,\
        #                     O=self.__flag_O,\
        #                     routerlifetime=self.__routerlifetime,\
        #                     chlim=self.__flag_chlim)
        # tr1_pd = ICMPv6NDOptPrefixInfo(L=self.__flag_L,\
        #                                 A=self.__flag_A,\
        #                                 R=self.__flag_R,\
        #                                 validlifetime=self.__validlifetime,\
        #                                 preferredlifetime=self.__preferredlifetime,\
        #                                 prefix=self.__global_addr)
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.icmpv6_ra(fields)/\
            self.icmpv6_pd(fields),\
            iface=self.__wan_device_tr1,inter=1)

    def send_dhcp_advertise(self,fields=None):
        #sendp(Ether()/IPv6()/UDP()/DHCP6_Advertise()/DHCP6OptClientId()/DHCP6OptServerId()/DHCP6OptIA_NA()/DHCP6OptIA_PD()/DHCP6OptDNSServers()/DHCP6OptDNSDomains(),iface='lo')
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.udp()/\
            self.dhcp_advertise()/\
            self.dhcp_client_id(fields)/\
            self.dhcp_server_id(fields)/\
            self.opt_ia_na(fields)/\
            self.opt_ia_pd(fields)/\
            self.opt_dns_server()/\
            self.opt_dns_domain(),\
            iface=self.__wan_device_tr1,inter=1)

    def send_dhcp_reply(self,fields=None):
        #sendp(Ether()/IPv6()/UDP()/DHCP6_Advertise()/DHCP6OptClientId()/DHCP6OptServerId()/DHCP6OptIA_NA()/DHCP6OptIA_PD()/DHCP6OptDNSServers()/DHCP6OptDNSDomains(),iface='lo')
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.udp()/\
            self.dhcp_reply(fields)/\
            self.opt_ia_na(fields)/\
            self.opt_ia_pd(fields)/\
            self.opt_dns_server()/\
            self.opt_dns_domain(),\
            iface=self.__wan_device_tr1,inter=1)

    def send_echo_request(self,fields=None,contador=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.echo_request(),\
            iface=self.__wan_device_tr1,count=contador,inter=1)
            
    def send_icmp_ns(self,fields=None,contador=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.icmpv6_ns(fields),\
            iface=self.__wan_device_tr1,inter=1)

    def send_dhcp_reconfigure(self,fields=None):
        #sendp(Ether()/IPv6()/UDP()/DHCP6_Advertise()/DHCP6OptClientId()/DHCP6OptServerId()/DHCP6OptIA_NA()/DHCP6OptIA_PD()/DHCP6OptDNSServers()/DHCP6OptDNSDomains(),iface='lo')
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.udp()/\
            self.dhcp()/\
            self.dhcp_client_id(fields)/\
            self.dhcp_server_id(fields)/\
            self.dhcp_reconfigure(fields)/\
            self.dhcp_auth(),\
            #self.opt_ia_na()/\
            #self.opt_ia_pd()/\
            #self.opt_dns_server()/\
            #self.opt_dns_domain(),\
            iface=self.__wan_device_tr1,inter=1)