""" Engine Module """

import logging
from cerouter import CeRouter
#exemplo testes em nodes, Telefones VOIP, etc

format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")
class Engine:

    def __init__(self):
        self.__profiles_list = []
        self.__active_profile = None
        # self.__jiga_id = jiga_id
        # self.__connector = connector

    def load_profiles(self, config):
        self.add_profile(CeRouter(config))
        #self.add_profile(Hosts())
        #self.add_profile(ATA_VOIP())



    # def notify_server_connected(self, jiga_id):
    # 	if self.__jiga_id != jiga_id:
    # 		logging.error(\
    # 			'Engine - received notification with incorrect jiga id.')
    # 		return False

    # 	self.__connector.set_connected()
    # 	return True

    def add_profile(self, profile):
        self.__profiles_list.append(profile)

    def profiles_number(self):
        return len(self.__profiles_list)

    def set_profile(self, profile_name):

    #		logging.debug("Engine - Setting profile to " + profile_name)

        for profile in self.__profiles_list:

            #print(profile)
            if profile.get_name() == profile_name:

                self.__active_profile = profile

                self.__active_profile.activate()


    def get_active_profile_name(self):
        if not self.__active_profile:
            return ''

        return self.__active_profile.get_name()

    def get_programmed_steps_number(self):
        if not self.__active_profile:
            return 0

        return self.__active_profile.steps_number()

    def start(self):

        if not self.__active_profile:
            raise RuntimeError('No profile active')

        profile_name = self.get_active_profile_name()

        logging.info('Application started with profile: ' + profile_name)

        #while True:
            #try:
        self.__active_profile.execute(profile_name)
        #    except BaseException as error:
        #        logging.error(error)

    def get_profile_names(self):
        profiles = []
        for profile in self.__profiles_list:
            profiles.append(profile.get_name())

        return profiles

    def get_profiles_conf(self):
        configs = {}
        for profile in self.__profiles_list:
            if profile.get_config():
                configs[profile.get_name()] = profile.get_config().getAll()
        return configs
