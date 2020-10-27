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
import codecs
import hmac
import codecs

format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")

log = logging.getLogger('scrapy')
log.setLevel(logging.ERROR)

class SendMsgs:

    def __init__(self,config):
        self.__queue_wan = Queue()
        self.__queue_lan = Queue()
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
        self.__my_key = b'TAHITEST89ABCDEF'
        self.__my_key_fake = b'TAHITEST89AAADEF'
        self.__my_key_msg = b'\x01\x54\x41\x48\x49\x54\x45\x53\x54\x38\x39\x41\x42\x43\x44\x45\x46'
        self.__rep = None    
        self.__rep_base = '1122334455667788'
        self.__lan_device = self.__config.get('lan','lan_device')
        self.__wan_device_tr1 = self.__config.get('wan','device_wan_tr1')
        self.__wan_mac_tr1 = self.__config.get('wan','wan_mac_tr1')
        self.__link_local_addr = self.__config.get('wan','link_local_addr')
        self.__all_nodes_addr = self.__config.get('multicast','all_nodes_addr')
        self.__global_addr = self.__config.get('wan','global_addr')
        self.__test_desc = self.__config.get('tests','common1-1')

    def client_fqdn(self,test=None):
        return DHCP6OptClientFQDN(fqdn= test.get_fdqn().encode())

    def dhcp(self,test=None):
        if test:
            return DHCP6(msgtype=int(test.get_dhcp_reconf_type()))
        else:
            return DHCP6()
    
    def dhcp_advertise(self,test=None):
        return DHCP6_Advertise(trid=test.get_xid())

    def dhcp_client_id_lan(self,test=None):
        return DHCP6OptClientId(duid=b'\x00\x01\x00\x01\x1f\xef\x03\x96\x44\x87\xfc\xba\xab\xab')

    def dhcp_client_id(self,test=None):
        return DHCP6OptClientId(duid=test.get_client_duid())

    def dhcp_information(self,test=None):
        return DHCP6_InfoRequest(trid=int(test.get_xid().encode(),16))

    def dhcp_solicit(self,test=None):
        return DHCP6_Solicit(trid=int(test.get_xid().encode(),16))

    def dhcp_server_id(self,test=None):
        return DHCP6OptServerId(duid=b'\x00\x01\x00\x01\x1f\xef\x03\x96\x44\x87\xfc\xba\x75\x46')

    def dhcp_reply(self,test=None):
        return DHCP6_Reply(trid=test.get_xid())

    def dhcp_reconf_accept(self):
        return DHCP6OptReconfAccept()

    def dhcp_reconfigure(self,test):
        return DHCP6OptReconfMsg(msgtype=5)
    
    def dhcp_auth(self,test=None):
        return DHCP6OptAuth(replay=self.__rep,\
                            authinfo = self.__hexdigest)
                            
    def dhcp_auth2(self,test=None):
        return DHCP6OptAuth(replay=codecs.decode(self.__rep_base,'hex_codec'),\
                            authinfo = self.__my_key_msg)

    def dhcp_auth_zero(self):
        return DHCP6OptAuth(replay=self.__rep,\
                            authinfo = b'\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def ether(self,test=None):
        return Ether(src= test.get_ether_src() if test else self.__wan_mac_tr1,\
                dst = test.get_ether_dst() if test else None)

    def echo_request(self):
        return ICMPv6EchoRequest()

    def echo_reply(self):
        return ICMPv6EchoReply()

    def elapsedtime(self,test=None):
        return DHCP6OptElapsedTime(elapsedtime= test.get_elapsetime())


    def ipv6(self,test=None):
        return IPv6(src=test.get_ipv6_src() if test else self.__link_local_addr,\
                    dst= test.get_ipv6_dst() if test else self.__all_nodes_addr)
                      
    def icmpv6_ra2(self,test=None):
        return ICMPv6ND_RA(M=test.get_flag_M(),\
                            O=test.get_flag_O(),\
                            prf = test.get_flag_prf(),\
                            reachabletime = test.get_reachabletime(),\
                            retranstimer = test.get_retranstimer(),\
                            routerlifetime=test.get_routerlifetime(),\
                            chlim=test.get_flag_chlim())

    def icmpv6_ra(self,test=None):
        return ICMPv6ND_RA(M=test.get_flag_M(),\
                            O=test.get_flag_O(),\
                            prf = test.get_flag_prf(),\
                            routerlifetime=test.get_routerlifetime(),\
                            chlim=test.get_flag_chlim())

    def icmpv6_pd(self,test=None):
        if test.get_pd_prefixlen() == None:
            return ICMPv6NDOptPrefixInfo(L=test.get_flag_L(),\
                                        A=test.get_flag_A(),\
                                        R=test.get_flag_R(),\
                                        validlifetime=test.get_validlifetime(),\
                                        preferredlifetime=test.get_preferredlifetime(),\
                                        prefix=self.__config.get('wan','global_addr'))
        else:
            return ICMPv6NDOptPrefixInfo(L=test.get_flag_L(),\
                                        A=test.get_flag_A(),\
                                        R=test.get_flag_R(),\
                                        prefixlen= test.get_pd_prefixlen(),\
                                        validlifetime=test.get_validlifetime(),\
                                        preferredlifetime=test.get_preferredlifetime(),\
                                        prefix=self.__config.get('wan','global_addr'))

    def icmpv6_ns(self,test=None):
        return ICMPv6ND_NS(tgt=test.get_tgt())

    def icmpv6_rs(self,test=None):
        return ICMPv6ND_RS()


    def icmpv6_lla_dst_lan(self,test=None):
        return ICMPv6NDOptDstLLAddr(lladdr=test.get_lla())

    def icmpv6_lla(self,test=None):
        return ICMPv6NDOptDstLLAddr(lladdr=test.get_lla())

    def icmpv6_src_lla(self,test=None):
        return ICMPv6NDOptSrcLLAddr(lladdr=test.get_lla())


    def icmpv6_na(self,test=None):
        return ICMPv6ND_NA(S=1,\
                            R=1,\
                            O=1,\
                tgt=test.get_tgt())

    def icmpv6_lla_lan(self,test=None):
        return ICMPv6NDOptSrcLLAddr(lladdr=test.get_lla())

    def icmpv6_na_lan(self,test=None):
        return ICMPv6ND_NA(S=1,\
                            R=1,\
                            O=1,\
                tgt=test.get_tgt())



    def opt_dns_server(self):
        return DHCP6OptDNSServers(dnsservers=[self.__config.get('setup1-1_advertise','dns_rec_name_server')])

    def opt_dns_domain(self):
        return DHCP6OptDNSDomains(dnsdomains=[self.__config.get('setup1-1_advertise','domain_search')])

    def opt_ia_pd(self,test=None):
        if test.get_dhcp_plen() == None:
            return DHCP6OptIA_PD(iaid =test.get_iaid(),\
                                T1 = int(self.__config.get('setup1-1_advertise','t1')),\
                                T2 = int(self.__config.get('setup1-1_advertise','t2')),\
                                iapdopt=DHCP6OptIAPrefix(prefix = self.__config.get('setup1-1_advertise','ia_pd_address'),\
                                                            preflft = int(self.__config.get('setup1-1_advertise','ia_pd_pref_lifetime')),\
                                                            validlft = int(self.__config.get('setup1-1_advertise','ia_pd_validtime')),\
                                                            plen= int(self.__config.get('setup1-1_advertise','ia_pd_pref_len'))))
        else:
            return DHCP6OptIA_PD(iaid =test.get_iaid(),\
                                T1 = test.get_dhcp_t1(),\
                                T2 = test.get_dhcp_t2(),\
                                iapdopt=DHCP6OptIAPrefix(prefix = self.__config.get('setup1-1_advertise','ia_pd_address'),\
                                                            preflft = test.get_dhcp_preflft(),\
                                                            validlft = test.get_dhcp_validlft(),\
                                                            plen= test.get_dhcp_plen()))


    def opt_ia_pd_v3(self,test=None):
        print('opt_id')
        return DHCP6OptIA_PD(iaid =test.get_iaid(),\
                                T1 = test.get_dhcp_t1(),\
                                T2 = test.get_dhcp_t2(),\
                                iapdopt=DHCP6OptIAPrefix(prefix = test.get_prefix_addr(),\
                                                            preflft = test.get_dhcp_preflft(),\
                                                            validlft = test.get_dhcp_validlft(),\
                                                            plen= test.get_dhcp_plen()))

    def opt_ia_pd_v2(self,test=None):
        #print('opt_id')
        return DHCP6OptIA_PD(iaid =test.get_iaid(),\
                                T1 = test.get_dhcp_t1(),\
                                T2 = test.get_dhcp_t2(),\
                                iapdopt=DHCP6OptIAPrefix(prefix = self.__config.get('setup1-1_advertise','ia_pd_address'),\
                                                            preflft = test.get_dhcp_preflft(),\
                                                            validlft = test.get_dhcp_validlft(),\
                                                            plen= test.get_dhcp_plen() )/\
                                                            DHCP6OptIAPrefix(prefix=self.__config.get('setup1-1_advertise','ia_pd_address2'),\
                                                                            preflft=int(self.__config.get('t2.7.5a','dhcp_preflft2')),\
                                                                            validlft=int(self.__config.get('t2.7.5a','dhcp_validlft2')),\
                                                                            plen=int(self.__config.get('t2.7.5a','dhcp_plen2'))))
    def udp(self,test=None):
        return UDP()

    def udp_reconfigure(self,test=None):
        return UDP(sport=test.get_udp_sport(),\
                    dport=test.get_udp_dport())

    def opt_ia_na(self,test=None):
        return DHCP6OptIA_NA(iaid = test.get_iaid(),\
                            T1 = int(self.__config.get('setup1-1_advertise','t1')),\
                            T2 = int(self.__config.get('setup1-1_advertise','t2')),\
                            ianaopts=DHCP6OptIAAddress(addr=self.__config.get('setup1-1_advertise','ia_na_address'),\
                                                        preflft=int(self.__config.get('setup1-1_advertise','ia_na_pref_lifetime')),\
                                                        validlft=int(self.__config.get('setup1-1_advertise','ia_na_validtime'))))

    def opt_ia_na_lan(self,test=None):
        return DHCP6OptIA_NA(iaid = test.get_iaid(),\
                            T1 = int(self.__config.get('solicitlan','t1')),\
                            T2 = int(self.__config.get('solicitlan','t2')))
                           
    def opt_vendor_class(self,test=None):
        return DHCP6OptVendorClass(vcdata = test.get_vendor_class().encode() ,\
                                   enterprisenum= test.get_enterprise())

    def opt_req(self,test=None):
        return DHCP6OptOptReq(reqopts=[17,23,24,32]) 

    def send_tr1_RA(self,fields=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.icmpv6_ra(fields)/\
            self.icmpv6_pd(fields),\
            iface=self.__wan_device_tr1,inter=1,verbose=False)

    def send_tr1_RA2(self,fields=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.icmpv6_ra2(fields)/\
            self.icmpv6_pd(fields),\
            iface=self.__wan_device_tr1,inter=1,verbose=False)


    def send_tr1_RA_no_IA_PD(self,fields=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.icmpv6_ra(fields),\
            iface=self.__wan_device_tr1,inter=1,verbose=False)

    def send_dhcp_advertise(self,fields=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.udp()/\
            self.dhcp_advertise(fields)/\
            self.dhcp_client_id(fields)/\
            self.dhcp_server_id(fields)/\
            self.opt_ia_na(fields)/\
            self.opt_ia_pd(fields)/\
            self.opt_dns_server()/\
            self.opt_dns_domain(),\
            iface=self.__wan_device_tr1,inter=1,verbose=False)

    def send_dhcp_advertise_no_IA_PD(self,fields=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.udp()/\
            self.dhcp_advertise(fields)/\
            self.dhcp_client_id(fields)/\
            self.dhcp_server_id(fields)/\
            self.opt_ia_na(fields)/\
            self.opt_dns_server()/\
            self.opt_dns_domain(),\
            iface=self.__wan_device_tr1,inter=1,verbose=False)

    def send_dhcp_reply(self,fields=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.udp()/\
            self.dhcp_reply(fields)/\
            self.dhcp_client_id(fields)/\
            self.dhcp_server_id(fields)/\
            self.opt_ia_na(fields)/\
            self.opt_ia_pd(fields)/\
            self.dhcp_auth2()/\
            self.dhcp_reconf_accept()/\
            self.opt_dns_server()/\
            self.opt_dns_domain(),\
            iface=self.__wan_device_tr1,inter=1,verbose=False)

    def send_dhcp_reply_v2(self,fields=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.udp()/\
            self.dhcp_reply(fields)/\
            self.dhcp_client_id(fields)/\
            self.dhcp_server_id(fields)/\
            self.opt_ia_na(fields)/\
            self.opt_ia_pd_v2(fields)/\
            self.dhcp_auth2()/\
            self.dhcp_reconf_accept()/\
            self.opt_dns_server()/\
            self.opt_dns_domain(),\
            iface=self.__wan_device_tr1,inter=1,verbose=False)

    def send_dhcp_reply_v3(self,fields=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.udp()/\
            self.dhcp_reply(fields)/\
            self.dhcp_client_id(fields)/\
            self.dhcp_server_id(fields)/\
            self.opt_ia_na(fields)/\
            self.opt_ia_pd_v3(fields)/\
            self.dhcp_auth2()/\
            self.dhcp_reconf_accept()/\
            self.opt_dns_server()/\
            self.opt_dns_domain(),\
            iface=self.__wan_device_tr1,inter=1,verbose=False)

    def send_echo_request(self,fields=None,contador=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.echo_request()/\
            Raw(load='abcdef'),\
            iface=self.__wan_device_tr1,inter=1,verbose=False)

    def send_echo_request_lan(self,fields=None,contador=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.echo_request()/\
            Raw(load='abcdef'),\
            iface=self.__lan_device,inter=1,verbose=False)


    def send_echo_reply(self,fields=None,contador=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.echo_reply()/\
            Raw(load='abcdef'),\
            iface=self.__wan_device_tr1,inter=1,verbose=False)

            
    def send_icmp_ns(self,fields=None,contador=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.icmpv6_ns(fields)/\
            self.icmpv6_src_lla(fields),\
            iface=self.__wan_device_tr1,inter=1,verbose=False)

    def send_icmp_rs(self,fields=None,contador=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.icmpv6_rs(fields)/\
            self.icmpv6_src_lla(fields),\
            iface=self.__lan_device,inter=1,verbose=False)

    def send_icmp_na(self,fields=None,contador=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.icmpv6_na(fields)/\
            self.icmpv6_lla(fields),\
            iface=self.__wan_device_tr1,inter=1,verbose=False)

    def send_dhcp_reconfigure(self,fields=None):
        s = int(self.__rep_base,16) + 1
        s = str(hex(s).strip('0x'))
        self.__rep = codecs.decode(s,'hex_codec')
        a = self.dhcp(fields)
        b = self.dhcp_client_id(fields)
        c = self.dhcp_server_id(fields)
        d = self.dhcp_reconfigure(fields)
        e = self.dhcp_auth_zero()
        q = a/b/c/d/e
        key = hmac.new(self.__my_key,raw(q))
        self.__hexdigest = key.hexdigest()
        self.__hexdigest = '02' + self.__hexdigest
        self.__hexdigest =  codecs.decode(self.__hexdigest,'hex_codec')
   
        sendp(self.ether(fields)/\
            
            self.ipv6(fields)/\
            self.udp_reconfigure(fields)/\
            self.dhcp(fields)/\
            self.dhcp_client_id(fields)/\
            self.dhcp_server_id(fields)/\
            self.dhcp_reconfigure(fields)/\
            self.dhcp_auth(),\
            iface=self.__wan_device_tr1,inter=1,verbose=False)
        
    def send_dhcp_reconfigure_no_auth(self,fields=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.udp()/\
            self.dhcp(fields)/\
            self.dhcp_client_id(fields)/\
            self.dhcp_server_id(fields)/\
            self.dhcp_reconfigure(fields),\
            iface=self.__wan_device_tr1,inter=1,verbose=False)

    def send_dhcp_reconfigure_wrong(self,fields=None):
        s = int(self.__rep_base,16) + 1
        s = str(hex(s).strip('0x'))
        self.__rep = codecs.decode(s,'hex_codec')
        a = self.dhcp(fields)   
        b = self.dhcp_client_id(fields)
        c = self.dhcp_server_id(fields)
        d = self.dhcp_reconfigure(fields)
        e = self.dhcp_auth_zero()
        q = a/b/c/d/e
        key = hmac.new(self.__my_key_fake,raw(q))
        print(key.hexdigest())
        self.__hexdigest = key.hexdigest()
        self.__hexdigest = '02' + self.__hexdigest
        self.__hexdigest =  codecs.decode(self.__hexdigest,'hex_codec')
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.udp()/\
            self.dhcp(fields)/\
            self.dhcp_client_id(fields)/\
            self.dhcp_server_id(fields)/\
            self.dhcp_reconfigure(fields)/\
            self.dhcp_auth(),\
            iface=self.__wan_device_tr1,inter=1,verbose=False)

    def send_dhcp_information(self,fields=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.udp()/\
            self.dhcp_information(fields)/\
            self.elapsedtime(fields)/\
            self.dhcp_client_id_lan(fields)/\
            self.opt_vendor_class(fields)/\
            self.opt_req(fields),\
            iface=fields.get_lan_device(),inter=1,verbose=False)            

    def send_dhcp_solicit_ia_na(self,fields=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.udp()/\
            self.dhcp_solicit(fields)/\
            self.elapsedtime(fields)/\
            self.dhcp_client_id_lan(fields)/\
            self.client_fqdn(fields)/\
            self.opt_vendor_class(fields)/\
            self.opt_ia_na_lan(fields)/\
            self.opt_req(fields),\
            iface=self.__lan_device,inter=1,verbose=False)

    def send_icmp_na_lan(self,fields=None,contador=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.icmpv6_na_lan(fields)/\
            self.icmpv6_lla_dst_lan(fields),\
            iface=self.__lan_device,inter=1,verbose=False)

    def send_icmp_ns_lan(self,fields=None,contador=None):
        sendp(self.ether(fields)/\
            self.ipv6(fields)/\
            self.icmpv6_ns(fields)/\
            self.icmpv6_src_lla(fields),\
            iface=self.__lan_device,inter=1,verbose=False)
