""" Config Module """

import json
import base64
from configparser import ConfigParser


class Config:

	def __init__(self, configparser, filename):
		self.__config = configparser
		self.__filename = filename
		self.__config.add_section('directories')
		self.init_password()

	def init_password(self):
		try:
			self.get('security', 'password')
		except:
			self.set('security', 'password', base64.b64encode(b'lockinet').decode('utf-8'))
			self.save(json.dumps(self.to_dict()))

	def get(self, section, item):
		return self.__config.get(section, item)


	def set(self, section, item, value):
		try:
			self.__config.set(section, item, value)
		except:
			self.__config.add_section(section)
			self.__config.set(section, item, value)

	def to_dict(self):
		config_dict = {}
		for section in self.__config.sections():
			if not section in config_dict:
				config_dict[section] = {}
			for key, value in self.__config.items(section):
				config_dict[section][key] = value
		return config_dict

	def save(self, data):
		self.__config.read_dict(json.loads(data))
		if 'directories' in self.__config:
			del self.__config['directories']
		if 'profiles_conf' in self.__config:
			del self.__config['profiles_conf']
		file = open(self.__filename, 'w')
		self.__config.write(file)