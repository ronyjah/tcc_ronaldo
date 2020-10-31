from profile import Profile
import logging
from test161 import Test161
from test162a import Test162a
from test162b import Test162b
from test163a import Test163a
from test163b import Test163b
from test163c import Test163c
from test163d import Test163d
from test164a import Test164a
from test166a import Test166a
from test166b import Test166b
from test167 import Test167
from test271a import Test271a
from test271b import Test271b
from test271c import Test271c
from test272a import Test272a
from test272b import Test272b
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
from threading import Thread
import time
from flask import Flask,send_file,g,current_app,session
from flask_cors import CORS
format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
app = Flask(__name__)
class CeRouter(Profile):

    def __init__(self,config):
        Profile.__init__(self,'CeRouter',config=config)
        self.__config = config
        self.__previous_mac = ''
        self.__app = app
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
        self.iperf = None
        self.active = False
        self.number_tests = 18
        self.initapp()
        self.__t_flask =  Thread(target=self.start_flask,name='Flask server',daemon=False)
        self.__t_flask.start()

    def unlock_test(self):
        self.active = False

    def configure_interface(self, conf_name, ip):
        lan_device = self.__config.get('jiga', conf_name)

    def configure_interfaces(self):
        self.configure_interface('lan_device', '192.168.1.2')

    def wait_lan_connect(self):
        print("WAIT_LAN_CONNECT LOADED")
        device = self.__config.get('jiga', 'lan_device')

    def get_number_tests(self):
        return self.number_tests
    def initapp(self):
        @self.__app.route("/active/<test>",methods=['GET'])
        def enviar(test):

            if test == 'Test324':
                self.add_step(Test324(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: 3.2.4'

            elif test == 'Test323b':
                self.add_step(Test323b(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: 3.2.3b'

            elif test == 'Test323a':
                self.add_step(Test323a(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: 3.2.3a'

            elif test == 'Test322a':
                self.add_step(Test322a(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: 3.2.2a'

            elif test == 'Test322b':
                self.add_step(Test322b(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: 3.2.2b'

            elif test == 'Test321a':
                self.add_step(Test321a(self.__config,app))
                self.active = True

                return 'Test RFC 7084 Item: 3.2.1a'

            elif test == 'Test321b':
                self.add_step(Test321b(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: 3.2.1b'

            elif test == 'Test277a':
                self.add_step(Test277a(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: 2.7.7a'

            elif test == 'Test277b':
                self.add_step(Test277b(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: 2.7.7b'

            elif test == 'Test277c':
                self.add_step(Test277c(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: 2.7.7c'

            elif test == 'Test276':
                self.add_step(Test276(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: 2.7.6'

            elif test == 'Test275a':
                self.add_step(Test275a(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test275a'

            elif test == 'Test275b':
                self.add_step(Test275b(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test2.7.5.b'

            elif test == 'Test275c':
                self.add_step(Test275c(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test2.7.5.c'

            elif test == 'Test275d':
                self.add_step(Test275d(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test2.7.5.d'

            elif test == 'Test274a':
                self.add_step(Test274a(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test2.7.4.a'

            elif test == 'Test274b':
                self.add_step(Test274b(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test2.7.4.b'
            elif test == 'Test273a':
                self.add_step(Test273a(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test2.7.3.a'

            elif test == 'Test273b':
                self.add_step(Test273b(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test2.7.3.b'
            elif test == 'Test273c':
                self.add_step(Test273c(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test2.7.3.c'
            elif test == 'Test272a':
                self.add_step(Test272a(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test2.7.2.a'

            elif test == 'Test272b':
                self.add_step(Test272b(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test2.7.2.b'


            elif test == 'Test272c':
                self.add_step(Test272c(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test2.7.2c'

            elif test == 'Test271a':
                self.add_step(Test271a(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test2.7.1.a'

            elif test == 'Test271b':
                self.add_step(Test271b(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test2.7.1.b'

            elif test == 'Test271c':
                self.add_step(Test271c(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test2.7.1.c'

            elif test == 'Test167':
                self.add_step(Test167(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test1.6.7'

            elif test == 'Test166a':
                self.add_step(Test166a(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test1.6.6.a'

            elif test == 'Test166b':
                self.add_step(Test166b(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test1.6.6.b'

            elif test == 'Test164a':
                self.add_step(Test164a(self.__config,app))
                self.active = True

                return 'Test RFC 7084 Item: Test1.6.4.a'

            elif test == 'Test163a':
                self.add_step(Test163a(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test1.6.3.a'

            elif test == 'Test163b':
                self.add_step(Test163b(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test1.6.3.b'

            elif test == 'Test163c':
                self.add_step(Test163c(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test1.6.3.c'

            elif test == 'Test163d':
                self.add_step(Test163d(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test1.6.3.d'

            elif test == 'Test162a':
                self.add_step(Test162a(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test1.6.2.a'


            elif test == 'Test162b':
                self.add_step(Test162b(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test1.6.2.b'


            elif test == 'Test161':
                self.add_step(Test161(self.__config,app))
                self.active = True
                return 'Test RFC 7084 Item: Test1.6.1'
    def activate(self):
        logging.info('CeRouter: profile activating')               
        while not (self.active):
            time.sleep(5)
            logging.info('CeRouter: Aguardando a seleção do Teste pelo FrontEnd')


         



    def start_flask(self):
        CORS(self.__app)
        self.__app.config["SECRET_KEY"] = 'olamundo'
        self.__app.run(host='0.0.0.0')


