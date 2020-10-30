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

class ConfigSetup1_1_Lan:

    def __init__(self,config,interface):
        self.__config = config
        self.__interface = None
        self.__pkt = None
        self.__valid = False
        self.__result = None
        self.__device_lan_tn1 = None
        self.__lan_mac_tn1 = None
        self.__ceRouter_mac_addr = None
        self.__flag_M = None
        self.__flag_O = None
        self.__flag_chlim = None
        self.__flag_L = None
        self.__flag_A = None
        self.__flag_R = None
        self.__validlifetime = None
        self.__preferredlifetime = None
        self.__interval = None
        self.__routerlifetime = None
        self.__ipv6_dst =None
        self.__ipv6_src = None
        self.__ether_src = None
        self.__ether_dst = None
        self.__xid = None
        self.__server_duid = None
        self.__client_duid = None
        self.__ND_local_OK = False
        self.__setup1_1_OK = False
        self.__local_ping_OK = False
        self.__global_ns_ok = False
        self.__dhcp_ok = False
        self.__iaid = None
        self.__flag_prf = None
        self.__prefixaddr_CeRouter =None
        self.__l_CeRouter =None
        self.__A_CeRouter =None
        self.__R_CeRouter =None
        self.__validlifetime_CeRouter =None
        self.__preferredlifetime_CeRouter =None
        self.__prefixlen_CeRouter =None
        self.__r_prefixaddr_CeRouter =None
        self.__r_plen_CeRouter =None
        self.__r_prf_CeRouter =None
        self.__r_rtlifetime_CeRouter =None
        self.__rdnss_dns_CeRouter =None
        self.__rdnss_lifetime_CeRouter  =None
        self.__domainname =None
        self.__domainname_lifetime_CeRouter  =None
        self.__linklayer_CeRouter = None
        self.__setup_lan_start = None
        self.__lla = None
        self.__routerlifetime_CeRouter = None
        self.__disapproved = False
        self.__dhcp_reconf_type = None
        self.__local_addr_ceRouter =None
        self.__recvd_dhcp_srcladdr = False
        self.__recvd_dhcp_rdnss = False
        self.__ND_global_OK = False
        self.__global_addr_ceRouter = None
        self.__global_mac_cerouter = None
        self.__ping_global = False
        self.__mac_cerouter = None
        self.__sendmsgssetup1_1 = SendMsgs(self.__config)
        self.__wan_device_tr1 = self.__config.get('wan','device_wan_tr1')
        self.__lan_device  = self.__config.get('lan','lan_device')
        self.__wan_mac_tr1 = self.__config.get('wan','wan_mac_tr1')
        self.__link_local_addr = self.__config.get('wan','link_local_addr')
        self.__all_nodes_addr = self.__config.get('multicast','all_nodes_addr')
        self.__test_desc = self.__config.get('tests','1.6.2b')
        self.__elapsetime = None
        self.__fdqn = None
        self.__vendor_class = None
        self.__enterprise = None
        self.opt_req = None
        self.send_solicit = False



    def send_icmpv6_ra(self,pkt):
        et = Ether(src=self.__wan_mac_tr1)

        ip = IPv6(src=self.__link_local_addr,\
                  dst=self.__all_nodes_addr)
        icmp_ra = ICMPv6ND_RA()
        sendp(et/ip/icmp_ra,iface=self.__wan_device_tr1)

    def send_echo_request_lan(self):
        et = Ether(src=self.__wan_mac_tr1,\
                   dst=self.__ceRouter_mac_addr)
        ip = IPv6(src=self.__link_local_addr,\
                  dst=self.__all_nodes_addr)
        icmp_ra = ICMPv6EchoRequest()
        sendp(et/ip/icmp_ra,iface=self.__wan_device_tr1)

    def flags_partA(self):
        self.__flag_M = self.__config.get('t1.6.2_flags_part_a','flag_m')
        self.__flag_O = self.__config.get('t1.6.2_flags_part_a','flag_o')
        self.__flag_chlim = self.__config.get('t1.6.2_flags_part_a','flag_chlim')
        self.__flag_L = self.__config.get('t1.6.2_flags_part_a','flag_l')
        self.__flag_A = self.__config.get('t1.6.2_flags_part_a','flag_a')
        self.__flag_R = self.__config.get('t1.6.2_flags_part_a','flag_r')
        self.__validlifetime = self.__config.get('t1.6.2_flags_part_a','validlifetime')
        self.__preferredlifetime = self.__config.get('t1.6.2_flags_part_a','preferredlifetime')
        self.__routerlifetime = self.__config.get('t1.6.2_flags_part_a','routerlifetime')
        self.__intervalo = self.__config.get('t1.6.2_flags_part_a','intervalo')

    def flags_partB(self):
        self.__flag_M = self.__config.get('t1.6.2_flags_part_b','flag_m')
        self.__flag_O = self.__config.get('t1.6.2_flags_part_b','flag_o')
        self.__flag_chlim = self.__config.get('t1.6.2_flags_part_b','flag_chlim')
        self.__flag_L = self.__config.get('t1.6.2_flags_part_b','flag_l')
        self.__flag_A = self.__config.get('t1.6.2_flags_part_b','flag_a')
        self.__flag_R = self.__config.get('t1.6.2_flags_part_b','flag_r')
        self.__validlifetime = self.__config.get('t1.6.2_flags_part_b','validlifetime')
        self.__preferredlifetime = self.__config.get('t1.6.2_flags_part_b','preferredlifetime')
        self.__routerlifetime = self.__config.get('t1.6.2_flags_part_b','routerlifetime')
        self.__intervalo = self.__config.get('t1.6.2_flags_part_b','intervalo')

#===========LAN======================

    def get_prefixaddr_CeRouter(self):
        return self.__prefixaddr_CeRouter
    def get_l_CeRouter(self):
        return self.__l_CeRouter 
    def get_A_CeRouter(self):
        return self.__A_CeRouter 
    def get_R_CeRouter(self):
        return self.__R_CeRouter 
    def get_validlifetime_CeRouter(self):
        return self.__validlifetime_CeRouter 
    def get_preferredlifetime_CeRouter(self):
        return self.__preferredlifetime_CeRouter
    
    def get_routerlifetime_CeRouter(self):    
        return self.__routerlifetime_CeRouter

    def get_prefixlen_CeRouter(self):
        return self.__prefixlen_CeRouter
    def get_r_prefixaddr_CeRouter(self):
        return self.__r_prefixaddr_CeRouter 
    def get_r_plen_CeRouter(self):
        return self.__r_plen_CeRouter
    def get_r_prf_CeRouter(self):
        return self.__r_prf_CeRouter 
    def get_r_lifetime_CeRouter(self):
        return self.__r_rtlifetime_CeRouter 
    def get_rdnss_dns_CeRouter(self):
        return self.__rdnss_dns_CeRouter
    def get_rdnss_lifetime_CeRouter(self):
        return self.__rdnss_lifetime_CeRouter 
    def get_domainname(self):
        return self.__domainname
    def get_domainname_lifetime_CeRouter(self):
        return self.__domainname_lifetime_CeRouter  
    def get_linklayer_CeRouter(self):
        return self.__linklayer_CeRouter 
   
    def get_lan_device(self):
        return self.__lan_device

    def get_setup_OK(self):
        return self.__setup1_1_OK

    def get_elapsetime(self):
        return int(self.__elapsetime)

    def set_elapsetime(self,valor):
        self.__elapsetime = valor

    def get_fdqn(self):
        return self.__fdqn
    
    def set_fdqn(self,valor):
        self.__fdqn = valor

    def get_vendor_class(self):
        return self.__vendor_class

    def set_vendor_class(self,valor):
        self.__vendor_class = valor

    def get_enterprise(self):
        return int(self.__enterprise)

    def set_enterprise(self,valor):
        self.__enterprise = valor 

    def get_opt_req(self):
        return self.opt_req

    def set_opt_req(self,valor):
        self.opt_req = valor




#=========== WAN/LAN===================

    def set_result(self, valor):
        self.__result = valor
        
    def get_result(self):
        return self.__result

    def get_flag_M(self):
        return int(self.__flag_M)

    def set_flag_M(self,valor):
        self.__flag_M = valor

    def get_flag_O(self):
        return int(self.__flag_O)

    def get_flag_prf(self):
        return int(self.__flag_prf)

    def set_flag_prf(self,valor):
        self.__flag_prf = valor

    def set_flag_0(self,valor):
        self.__flag_O = valor

    def set_routerlifetime(self,valor):
        self.__routerlifetime= valor

    def set_flag_L(self,valor):
        self.__flag_L = valor
        
    def set_flag_A(self,valor):
        self.__flag_A = valor

    def set_flag_R(self,valor):
        self.__flag_R = valor

    def set_validlifetime(self,valor):
        self.__validlifetime = valor

    def set_preferredlifetime(self,valor):
        self.__preferredlifetime = valor

    def set_intervalo(self,valor):
        self.__intervalo = valor
        
    def set_flag_chlim(self,valor):
        self.__flag_chlim = valor

    def get_flag_chlim(self):
        return int(self.__flag_chlim)

    def get_flag_L(self):
        return  int(self.__flag_L)

    def get_flag_A(self):
        return int(self.__flag_A)

    def get_flag_R(self):
        return int(self.__flag_R)

    def get_validlifetime(self):
        return int(self.__validlifetime)

    def get_preferredlifetime(self):
        return int(self.__preferredlifetime)

    def get_interval(self):
        return int(self.__intervalo)

    def get_routerlifetime(self):
        return int(self.__routerlifetime)
    
    def set_ipv6_dst(self, valor):
        self.__ipv6_dst = valor

    def get_ipv6_dst(self):
        return self.__ipv6_dst

    def set_ipv6_src(self, valor):
        self.__ipv6_src = valor

    def get_ipv6_src(self):
        return self.__ipv6_src

    def set_ether_dst(self, valor):
        self.__ether_dst = valor

    def get_ether_dst(self):
        return self.__ether_dst

    def set_ether_src(self, valor):
        self.__ether_src = valor

    def get_ether_src(self):
        return self.__ether_src
    
    def set_local_addr_ceRouter(self,valor):
        self.__local_addr_ceRouter = valor

    def get_local_addr_ceRouter(self):
        return self.__local_addr_ceRouter

    def get_global_addr_ceRouter(self):
        return self.__global_addr_ceRouter

    def set_tgt(self,valor):
        self.__tgt = valor

    def get_tgt(self):
        return self.__tgt

    def set_xid(self,valor):
        self.__xid = valor

    def get_xid(self):
        return self.__xid

    def set_client_duid(self,valor):
        self.__client_duid = valor

    def get_recvd_dhcp_rdnss(self):
        return self.__recvd_dhcp_rdnss
    def get_recvd_dhcp_srcladdr(self):
        return self.__recvd_dhcp_srcladdr


    def get_client_duid(self):
        return self.__client_duid

    def set_server_duid(self,valor):
        self.__server_duid = valor

    def get_server_duid(self):
        return self.__server_duid

    def set_iaid(self,valor):
        self.__iaid = valor

    def get_iaid(self):
        return int(self.__iaid,16)
    
    def get_local_ping(self):
        return self.__local_ping_OK

    def get_ND_local_OK(self):
        return  self.__ND_local_OK

    def get_ND_global_OK(self):
        return  self.__ND_global_OK

    def get_global_ping_OK(self):
        return self.__ping_global

    def get_dhcp_reconf_type(self):
        return self.__dhcp_reconf_type
    
    def set_dhcp_reconf_type(self,valor):
        self.__dhcp_reconf_type = valor

    def set_mac_ceRouter(self,valor):
        self.__mac_cerouter = valor

    def get_mac_ceRouter(self):
        return self.__mac_cerouter

    def get_global_mac_ceRouter(self):
        return self.__global_mac_cerouter

    def get_disapproved(self):
        return self.__disapproved
    def get_lla(self):
        return self.__lla

    def set_lla(self,valor):
        self.__lla = valor
    def set_setup_lan_start(self):
        self.__setup_lan_start = True


        
    def run_setup1_1(self,pkt):
        

        if not self.__setup_lan_start:
            return
        if self.__disapproved:
            return False
        if pkt[Ether].src == self.__config.get('lan','mac_address'):
            return
        if pkt[Ether].src == self.__config.get('lan','mac'):
            return
        if self.__disapproved:
            return False

        if not pkt.haslayer(ICMPv6NDOptPrefixInfo):
            pass

        if pkt.haslayer(ICMPv6EchoReply):
            if pkt[IPv6].src == self.__global_addr_ceRouter:
                self.__ping_global = True
                
        if pkt.haslayer(ICMPv6ND_NS):

            prefix = pkt[ICMPv6ND_NS].tgt
            if prefix[:4] == 'fe80':
                self.__local_addr_ceRouter = (pkt[ICMPv6ND_NS].tgt)
                self.__mac_cerouter = (pkt[Ether].src)
                self.__ND_local_OK = True
                
            if prefix[:4] == (self.__config.get('wan','global_wan_addr'))[:4]:

                if prefix != self.__config.get('lan','global_wan_addr'):
                    self.__global_addr_ceRouter = (pkt[ICMPv6ND_NS].tgt)
                    self.__global_mac_cerouter = (pkt[Ether].src)
                    self.__ND_global_OK = True

            if pkt[ICMPv6ND_NS].tgt == self.__config.get('lan','global_wan_addr'):
                self.set_ipv6_src(self.__config.get('lan','global_wan_addr'))
                self.set_ether_src(self.__config.get('lan','mac_address'))
                self.set_ether_dst(pkt[Ether].src)
                self.set_ipv6_dst(pkt[IPv6].src)
                self.set_tgt(self.__config.get('lan','global_wan_addr'))
                self.set_lla(self.__config.get('lan','mac_address'))
                self.__sendmsgssetup1_1.send_icmp_na_lan(self)
        

        print('chegou RA PRA ESSE TESTE')
        pkt.show()
        if pkt.haslayer(ICMPv6ND_RA):
            self.__routerlifetime_CeRouter = pkt[ICMPv6ND_RA].routerlifetime
            if pkt.haslayer(ICMPv6NDOptPrefixInfo):
                self.__prefixaddr_CeRouter = pkt[ICMPv6NDOptPrefixInfo].prefix
                self.__l_CeRouter = pkt[ICMPv6NDOptPrefixInfo].L
                self.__A_CeRouter = pkt[ICMPv6NDOptPrefixInfo].A
                self.__R_CeRouter = pkt[ICMPv6NDOptPrefixInfo].R
                self.__validlifetime_CeRouter = pkt[ICMPv6NDOptPrefixInfo].validlifetime
                self.__preferredlifetime_CeRouter = pkt[ICMPv6NDOptPrefixInfo].preferredlifetime
                self.__prefixlen_CeRouter = pkt[ICMPv6NDOptPrefixInfo].prefixlen
                self.send_solicit = True
                self.__setup1_1_OK = True
                #return
            print('CHegou RA na LAN')
            if pkt.haslayer(ICMPv6NDOptRouteInfo):
                self.__r_prefixaddr_CeRouter = pkt[ICMPv6NDOptRouteInfo].prefix
                self.__r_plen_CeRouter = pkt[ICMPv6NDOptRouteInfo].plen
                self.__r_prf_CeRouter = pkt[ICMPv6NDOptRouteInfo].prf
                self.__r_rtlifetime_CeRouter = pkt[ICMPv6NDOptRouteInfo].rtlifetime

            if pkt.haslayer(ICMPv6NDOptRDNSS):
                self.__rdnss_dns_CeRouter = pkt[ICMPv6NDOptRDNSS].dns
                self.__rdnss_lifetime_CeRouter = pkt[ICMPv6NDOptRDNSS].lifetime
                self.__recvd_dhcp_rdnss = True
   
            if pkt.haslayer(ICMPv6NDOptDNSSL):
                self.__domainname = pkt[ICMPv6NDOptDNSSL].searchlist
                self.__domainname_lifetime_CeRouter = pkt[ICMPv6NDOptDNSSL].lifetime
                self.__recvd_dhcp_srcladdr = True  

            if pkt.haslayer(ICMPv6NDOptSrcLLAddr):
                self.__linklayer_CeRouter = pkt[ICMPv6NDOptSrcLLAddr].lladdr

        
