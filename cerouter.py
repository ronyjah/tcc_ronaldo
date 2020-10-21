from profile import Profile
import logging
from test161 import Test161
from test162a import Test162a
from test162b import Test162b
from test162c import Test162c
from test163a import Test163a
from test163b import Test163b
from test163c import Test163c
from test163d import Test163d
from test164a import Test164a
from test166a import Test166a
from test166b import Test166b
from test167 import Test167
from test271a import Test271a
from test273a import Test273a
from test273b import Test273b
from test273c import Test273c
from test274a import Test274a
from test274b import Test274b
from test275a import Test275a
from test275b import Test275b
from test275c import Test275c
from test275d import Test275d
from test276 import Test276
from test277a import Test277a
from test277b import Test277b
from test277c import Test277c
from test321a import Test321a
from test321b import Test321b
from test322a import Test322a
from test322b import Test322b
from test323a import Test323a
from test323b import Test323b
from test324 import Test324
format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")
class CeRouter(Profile):

    def __init__(self,config):
        Profile.__init__(self,'CeRouter',config=config)
        self.__config = config
        self.__previous_mac = ''
        
        self.__device_lan_tn1 = None
        self.__lan_mac_tn1 = None
        self.__device_wan_tr1 = None
        self.__wan_mac_tr1 = None

        self.__all_nodes_addr = None
        self.__all_routers_addr = None
        self.__mldv2_addr = None
        self.__link_local_addr = None
        self.mac_input = None
        self.__session = None
        #self.router = OntRouter(config)
        self.iperf = None

	# def set_previous_mac(self, mac_value):
	# 	self.__previous_mac = mac_value

	# def get_previous_mac(self):
	# 	return self.__previous_mac

    def configure_interface(self, conf_name, ip):
        lan_device = self.__config.get('jiga', conf_name)
        #shell('ifconfig ' + lan_device + ' ' + ip + '/24 up')
        # shell('route add default gw 10.0.0.1 ' + lan_device)

    def configure_interfaces(self):
        self.configure_interface('lan_device', '192.168.1.2')

    def wait_lan_connect(self):
        print("WAIT_LAN_CONNECT LOADED")
        device = self.__config.get('jiga', 'lan_device')
    #lan_interface = Interface(device)
    #self.add_step(WaitLanConnect(lan_interface, 10, self.view))

	# def iperf_test(self):
	# 	chinese_address = self.__config.get('iperf', 'server_chinese')
	# 	intelbras_address = self.__config.get('iperf', 'server_intelbras')
	# 	test_time = self.__config.get('iperf', 'time')
	# 	min_rate = self.__config.get('iperf', 'min_rate')
	# 	retries = self.__config.get('iperf', 'retries')
	# 	iperf_test = IperfTest(chinese_address, intelbras_address,\
	# 						test_time, min_rate, self.view, retry=retries)
	# 	self.add_step(iperf_test) #FIXME: REFACT: pass config to IPERF test
	# 	self.iperf = iperf_test

    def activate(self):
        logging.info('CeRouter: profile activating')
        #self.configure_interfaces()
        #self.wait_lan_connect()
        #self.add_step(Test161(self.__config))
        #self.add_step(Test162a(self.__config))
        #self.add_step(Test162b(self.__config))
        #self.add_step(Test163a(self.__config))
        #self.add_step(Test163b(self.__config))
        #self.add_step(Test163c(self.__config))
        #self.add_step(Test163d(self.__config))
        #self.add_step(Test164a(self.__config))
        #self.add_step(Test166a(self.__config))
        #self.add_step(Test166b(self.__config))
        #self.add_step(Test167(self.__config))
        #self.add_step(Test271a(self.__config))
        #self.add_step(Test271b(self.__config))
        #self.add_step(Test272a(self.__config))
        #self.add_step(Test272b(self.__config))
        #self.add_step(Test272c(self.__config))
        #self.add_step(Test273a(self.__config))
        #self.add_step(Test273b(self.__config))
        #self.add_step(Test273c(self.__config))
        #self.add_step(Test274a(self.__config))
        #self.add_step(Test274b(self.__config))
        #self.add_step(Test275a(self.__config))
        #self.add_step(Test275b(self.__config))
        #self.add_step(Test275c(self.__config))
        #self.add_step(Test275d(self.__config))
        #self.add_step(Test276(self.__config))
        #self.add_step(Test277a(self.__config))
        #self.add_step(Test277b(self.__config))
        #self.add_step(Test277c(self.__config))
        #self.add_step(Test321a(self.__config))
        #self.add_step(Test321b(self.__config))
        #self.add_step(Test322a(self.__config))
        #self.add_step(Test322b(self.__config))
        #self.add_step(Test323a(self.__config))
        #self.add_step(Test323b(self.__config))
        self.add_step(Test324(self.__config))