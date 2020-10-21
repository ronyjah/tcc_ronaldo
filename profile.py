""" Profile Module """

from pathlib import Path
import os
import sys
import logging
import time
import json
import glob

STATISTICS_SIZE = 100

format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")
                    
class Profile:

    def __init__(self,name,config):
        self.__name = name
        self.__steps_list = []
        self.test_counter = -1
		# self.__lan_device = lan_device
		# self.view = view
		# self.server_connected = False
		# self.test_time_total = 0
		# self.op_time_total = 0

		# self.__test_times = list()
		# self.__op_times = list()
		# self.__results = list()
		# self.loadStats()
		# self.__previous_mac = ''
		# self.profile_conf = ProfileConf(name, config, router) if config else None
		# self.__config = config
		#if config:
	    #		self.check_versions_config(config)

#	def check_versions_config(self, config):
#		try:
#			version = config.get('versions', self.__name)
#		except:
#			config.set('versions', self.__name, '0.0.0')
#			config.save_copy(json.dumps(config.to_dict()))

    def wait_lan_connect(self, lan_interface):
        self.add_step(WaitLanConnect(lan_interface))

	# def set_previous_mac(self, mac_value):
	# 	self.__previous_mac = mac_value

	# def get_previous_mac(self):
	# 	return self.__previous_mac

	# def set_server_connected(self, status):
	# 	if self.server_connected != status:
	# 		logging.debug('Profile - server ' + \
	# 					 ('disconnected', 'connected')[status])

	# 	self.server_connected = status

    def get_name(self):
        return self.__name

    def add_step(self, step):
        self.__steps_list.append(step)

    def steps_number(self):
        return len(self.__steps_list)

	# def wait_server_connection(self, timeout):
	# 	logging.debug('Profile - waiting server connection.')
	# 	time_spent = 0.0
	# 	while not self.connector.is_connected():
	# 		time.sleep(0.1)
	# 		time_spent += 0.1
	# 		if time_spent > timeout:
	# 			return False

		# logging.debug('Profile - server connected.')
		# return True

	# def wait_server_disconnection(self, timeout):
	# 	logging.debug('Profile - waiting server disconnection.')
	# 	time_spent = 0.0
	# 	while self.connector.is_connected():
	# 		time.sleep(0.1)
	# 		time_spent += 0.1
	# 		if time_spent > timeout:
	# 			return False

	# 	logging.debug('Profile - server disconnected.')
	# 	return True

	# def append_times(self, test_time, op_time):
	# 	if len(self.__test_times) == STATISTICS_SIZE:
	# 		self.__test_times = self.__test_times[1:]
	# 		self.__op_times = self.__op_times[1:]

	# 	self.__test_times.append(test_time)
	# 	self.__op_times.append(op_time)

	# def append_result(self, result):
	# 	if len(self.__results) == STATISTICS_SIZE:
	# 		self.__results = self.__results[1:]
	# 	self.__results.append(result)

	# def saveStats(self):
	# 	data = {
	# 		'tt': self.__test_times,
	# 		'ot': self.__op_times,
	# 		'r' : self.__results
	# 	}
	# 	file = open('stats.json', 'w')
	# 	file.write(json.dumps(data))
	# 	file.close()

	# def loadStats(self):
	# 	try:
	# 		file = open('stats.json', 'r')
	# 		data = json.loads(file.read())
	# 		self.__test_times = data['tt']
	# 		self.__op_times = data['ot']
	# 		self.__results = data['r']
	# 	except Exception as error:
	# 		logging.warning('Profile - loadStats() - error loading stats.json!')
	# 		logging.warning(error)

	# def get_index_from_filename(self, filename):
	# 	index = filename[5:6]
	# 	return int(index)

	# def send_statistics(self):
	# 	try:
	# 		self.profiler.stop_op_time()

	# 		if self.profiler.get_op_time():
	# 			if self.profiler.get_op_time() > 300:
	# 				logging.warning('Profile - ignoring tmo')
	# 				return

	# 		test_time = self.profiler.get('test_time')[0]
	# 		op_time = self.profiler.get_op_time()
	# 		self.append_times(test_time, op_time)

	# 		self.test_time_total += test_time
	# 		self.op_time_total += op_time

	# 		files = [f for f in glob.glob("iperf*")]
	# 		iperf = []
	# 		for file in files:
	# 			iperf_file = open(file, 'r')
	# 			iperfStreamData = json.loads(iperf_file.read())
	# 			iperf_file.close()
	# 			index = self.get_index_from_filename(file)
	# 			iperf.insert(index, iperfStreamData)

	# 		stats = StatsEvent(self.__test_times, self.__op_times, self.__results, iperf)
	# 		self.view.set_event(stats)

	# 		self.saveStats()

	# 	except RuntimeError as error:
	# 		logging.error('Error on send statistics - ' + str(error))

	# def check_update(self):
	# 	update_path = '/opt/intelbras/jiga/daemon/update'
	# 	update_file = Path(update_path)
	# 	if update_file.is_file():
	# 		os.remove(update_path)
	# 		logging.debug('Updating \\o/')
	# 		shell('kill -9 ' + str(os.getpid()))

    def get_config(self):
        return self.profile_conf

    def execute(self, profile_name):
        logging.debug('Profile - executing profile ' + self.__name)

    #WaitLanDisconnect(self.__lan_device).run() #FIXME: refact - turn it into a specific profile dependency
        #print("1")
        #self.check_update()
        #print("2")
        self.test_counter += 1
        #print("3")
        # if(self.test_counter > 0):
        # 	self.send_statistics()

        # self.profiler = Profiler(jiga_id, profile_name)
        # total_key = self.profiler.register_start_time('total')

        stepsNumber = len(self.__steps_list)
        stepsCounter = -1

        for step in self.__steps_list:
            #print("4")

            # step_key = self.profiler.register_start_time(type(step).__name__)
            # step.set_profiler(self.profiler)
            #print("5")
  
            progress = int(round((stepsCounter/stepsNumber) * 100))

            #self.view.set_event(ProgressEvent(progress))
            stepsCounter += 1
            # print("a")
            # print("STEP.run in")
            
            test_ok = step.run()
            # print("STEP.run out")
            # print("6666666")
            # self.profiler.set_total_time(step_key)

            if not test_ok:
                logging.info('FALSO')
                return False
                #self.profiler.set_total_time(total_key)
                #self.profiler.stop_all()
                #self.profiler.save_ticket(False)
                #logging.debug('Profile - report: ' + self.profiler.get_text_report())
                #self.append_result(0)


            # self.profiler.set_total_time(total_key)
            # self.profiler.save_ticket()
            # logging.debug('Profile - report: ' + self.profiler.get_text_report())
            #self.append_result(1)
            logging.info('VERDADEIRO')
            #return True

    #def inject_connector(self, connector):
    #self.connector = connector

    def configure_interfaces(self):
        device = self.__config.get('jiga', 'lan_device')
        ip = '10.0.0.2'

        try:
            ip = self.__config.get('jiga', 'local_ip')
        except:
            logging.info('Profile: using default ip to setup interface: 10.0.0.2')

        # while not ping(ip):
        #     logging.debug('Profile: configuring interface')
        #     shell('ifconfig ' + device + ' ' + ip + '/24 up')
        #     time.sleep(1)
        # logging.debug('Profile: local interface configured')

    def activate(self):
        """ Needs to be implemented by derived class """
        pass
