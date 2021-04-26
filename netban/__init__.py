#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import configparser
import logging
import asyncio

class NetBanConfig(object):
	"""Loads the config from file"""
	def __init__(self, config_file_name):
		super(NetBanConfig, self).__init__()
		self.__logger = logging.getLogger('netban.config')
		cfg = configparser.ConfigParser()
		cfg.read(config_file_name)
		self.__logger.info("Read and parsed config file <%s>." % config_file_name)
		self.cfg = cfg

	def get_local_file(self):
		"""Convenience method for getting the local file to watch."""
		return self.cfg['local'].get('file')

	def get_redis_db(self):
		"""Convenience method for getting the redis db to use."""
		return self.cfg['local'].getint('db')

	def get_ip_timeout(self):
		"""Convenience method for getting the timeout period for a single ip."""
		return self.cfg['local'].getint('timeout')

	def get_ip_limit(self):
		"""Convenience method for getting the max failed attempts for a single ip."""
		return self.cfg['local'].getint('limit')

	def get_rule_number(self):
		"""Convenience function for getting the location to insert rules in iptables."""
		return self.cfg['general'].getint('rulenum')

	def get_net_query_distance(self):
		"""Convenience function for getting the timespan for the net query."""
		return self.cfg['net'].get('distance')

	def get_net_agg_field(self):
		"""Convenience function for getting the field to aggregate across."""
		return self.cfg['net'].get('aggregate')

	def get_net_count_field(self):
		"""Convenience function for getting the field to count (cardinality)."""
		return self.cfg['net'].get('cardinality')

	def get_net_limit(self):
		"""Convenience function for getting the aggregation size limit."""
		return self.cfg['net'].getint('limit')

	def get_net_filter_field(self):
		"""Convenience function for getting the field to filter on."""
		return self.cfg['net'].get('filter-field')

	def get_net_filter_term(self):
		"""Convenience function for getting the term to filter on."""
		return self.cfg['net'].get('filter-term')

	def get_elastic_uri(self):
		"""Convenience function for getting the Elasticsearch URI."""
		return self.cfg['net'].get('elastic-uri')

	def get_net_buckets(self):
		"""Convenience function for getting the number of aggregation buckets."""
		return self.cfg['net'].get('buckets')

class NetBanManager(object):
	"""Interface with iptables/ipset to manage bans"""
	def __init__(self, config):
		super(NetBanManager, self).__init__()
		self.__logger = logging.getLogger('netban.banmanager')
		self.cfg = config
		self.initialized = False

	async def setup(self):
		"""Get the sets created and inserted in iptables"""
		# Create sets
		p = await asyncio.create_subprocess_exec('/usr/sbin/ipset','create','netbanlocal','hash:ip')
		r = await p.wait()
		assert r == 0, "Creation of netbanlocal set failed."
		self.__logger.debug("Created netbanlocal set.")
		p = await asyncio.create_subprocess_exec('/usr/sbin/ipset','create','netbannet','hash:net')
		r = await p.wait()
		assert r == 0, "Creation of netbannet set failed."
		self.__logger.debug("Created netbannet set.")
		# Add sets to iptables 
		insert_at = self.cfg.get_rule_number()
		p = await asyncio.create_subprocess_exec('/usr/sbin/iptables','-I','INPUT','%d' % insert_at,'-m','set','--match-set','netbanlocal','src','-j','DROP')
		r = await p.wait()
		assert r == 0, "Inserting netbanlocal rule failed."
		self.__logger.debug("Added netbanlocal rule.")
		p = await asyncio.create_subprocess_exec('/usr/sbin/iptables','-I','INPUT','%d' % insert_at,'-m','set','--match-set','netbannet','src','-j','DROP')
		r = await p.wait()
		assert r == 0, "Inserting netbannet rule failed."
		self.__logger.debug("Added netbannet rule.")

		self.initialized = True

	async def ban(self, ip):
		"""Add an IP address to the ban set."""
		self.__logger.debug("Received request to ban ip %s." % ip)
		p = await asyncio.create_subprocess_exec('/usr/sbin/ipset','add','netbanlocal',ip)
		r = await p.wait()
		assert r == 0, "Adding %s to netbanlocal set failed." % ip
		self.__logger.debug("%s added to netbanlocal set." % ip)

	async def unban(self, ip):
		"""Remove an IP address from the ban set."""
		self.__logger.debug("Received request to unban ip %s." % ip)
		p = await asyncio.create_subprocess_exec('/usr/sbin/ipset','del','netbanlocal',ip)
		r = await p.wait()
		assert r == 0, "Removing %s from netbanlocal set failed." % ip
		self.__logger.debug("%s removed from netbanlocal set." % ip)

	async def netban(self, cidr):
		"""Add a CIDR-notation net to the ban set."""
		self.__logger.debug("Received request to ban net %s." % cidr)
		p = await asyncio.create_subprocess_exec('/usr/sbin/ipset','add','netbannet',cidr)
		r = await p.wait()
		assert r == 0, "Adding %s to netbannet set failed." % cidr
		self.__logger.debug("%s added to netbannet set." % cidr)

	async def netunban(self, cidr):
		"""Remove a CIDR-notation net from the ban set."""
		self.__logger.debug("Received request to unban net %s." % cidr)
		p = await asyncio.create_subprocess_exec('/usr/sbin/ipset','del','netbannet',cidr)
		r = await p.wait()
		assert r == 0, "Removing %s from netbannet set failed." % cidr
		self.__logger.debug("%s removed from netbannet set." % cidr)
