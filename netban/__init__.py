#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import configparser
import logging

class NetBanConfig(object):
	"""Loads the config from file"""
	def __init__(self, config_file):
		super(NetBanConfig, self).__init__()
		self.__logger = logging.getLogger('netban.config')
		cfg = configparser.ConfigParser()
		cfg.read(config_file)
		self.__logger.info("Read and parsed config file <%s>." % config_file)
		self.cfg = cfg

	def get_local_file(self):
		"""Convenience method for getting the local file to watch."""
		raise NotImplementedError("Not yet finished.")

	def get_redis_db(self):
		"""Convenience method for getting the redis db to use."""
		raise NotImplementedError("Not yet finised.")

	def get_ip_timeout(self):
		"""Convenience method for getting the timeout period for a single ip."""
		raise NotImplementedError("Not yet finished.")

	def get_ip_limit(self):
		"""Convenience method for getting the max failed attempts for a single ip."""
		raise NotImplementedError("Not yet finished.")