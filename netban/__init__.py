#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import configparser
import logging
import asyncio
import os
from subprocess import PIPE

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

	def get_elastic_host(self):
		"""Convenience function for getting the Elasticsearch host."""
		# Starting this as a list so it's easier to extend for multiple hosts later.
		return [self.cfg['net'].get('elastic-host')]

	def get_elastic_index(self):
		"""Convenience function for getting the Elasticsearch index pattern."""
		return self.cfg['net'].get('elastic-index')

	def get_net_buckets(self):
		"""Convenience function for getting the number of aggregation buckets."""
		return self.cfg['net'].get('buckets')

	def get_net_interval(self):
		"""Convenience function for getting the refresh interval for the net query."""
		return self.cfg['net'].getint('interval')

	def get_net_retry_interval(self):
		"""Convenience function for getting the Elastic retry interval."""
		return self.cfg['net'].getint('retry-interval')

class NetBanManager(object):
	"""Interface with iptables/ipset to manage bans"""
	def __init__(self, config):
		super(NetBanManager, self).__init__()
		self.__logger = logging.getLogger('netban.banmanager')
		self.cfg = config
		self.initialized = False

	async def setup(self):
		"""Get the sets created and inserted in iptables"""
		# Find external executables to use.
		self.ipset = self.whichIpset()
		self.__logger.debug("Using ipset from %s" % self.ipset)
		self.iptables = self.whichIptabes()
		self.__logger.debug("Using iptables from %s" % self.iptables)
		# Create sets
		p = await asyncio.create_subprocess_exec(self.ipset,'create','netbanlocal','hash:ip')
		r = await p.wait()
		assert r == 0, "Creation of netbanlocal set failed."
		self.__logger.debug("Created netbanlocal set.")
		p = await asyncio.create_subprocess_exec(self.ipset,'create','netbannet','hash:net')
		r = await p.wait()
		assert r == 0, "Creation of netbannet set failed."
		self.__logger.debug("Created netbannet set.")
		# Add sets to iptables 
		insert_at = self.cfg.get_rule_number()
		p = await asyncio.create_subprocess_exec(self.iptables,'-I','INPUT','%d' % insert_at,'-m','set','--match-set','netbanlocal','src','-j','DROP')
		r = await p.wait()
		assert r == 0, "Inserting netbanlocal rule failed."
		self.__logger.debug("Added netbanlocal rule.")
		p = await asyncio.create_subprocess_exec(self.iptables,'-I','INPUT','%d' % insert_at,'-m','set','--match-set','netbannet','src','-j','DROP')
		r = await p.wait()
		assert r == 0, "Inserting netbannet rule failed."
		self.__logger.debug("Added netbannet rule.")

		self.initialized = True

	@classmethod
	def whichIpset(cls):
		"""Find an executable version of ipset."""
		for ipset in ('/usr/sbin/ipset', '/sbin/ipset'):
			if os.path.exists(ipset) and os.access(ipset, os.X_OK):
				return ipset
		raise EnvironmentError('No executable `ipset` command found.')

	@classmethod
	def whichIptabes(cls):
		"""Find an executable version of iptables."""
		for iptables in ('/usr/sbin/iptables', '/sbin/iptables'):
			if os.path.exists(iptables) and os.access(iptables, os.X_OK):
				return iptables
		raise EnvironmentError('No executable `iptables` command found.')

	async def ban(self, ip):
		"""Add an IP address to the ban set."""
		self.__logger.debug("Received request to ban ip %s." % ip)
		p = await asyncio.create_subprocess_exec(self.ipset,'add','netbanlocal',ip)
		r = await p.wait()
		assert r == 0, "Adding %s to netbanlocal set failed." % ip
		self.__logger.debug("%s added to netbanlocal set." % ip)

	async def unban(self, ip):
		"""Remove an IP address from the ban set."""
		self.__logger.debug("Received request to unban ip %s." % ip)
		# First, see if the IP is in the set.
		self.__logger.debug("Finding netbanlocal set membership.")
		p = await asyncio.create_subprocess_exec(self.ipset,'list','netbanlocal', stdout=PIPE)
		(stdout, stderr) = await p.communicate()
		assert p.returncode == 0, "Error retrieving members of netbanlocal set."
		for line in stdout.decode('utf-8').split('\n'):
			if line == ip:
				self.__logger.debug("Found %s in set; will remove." % ip)
				break
		else:
			# This will execute if the IP is not found (no break).
			self.__logger.warning("%s not in netbanlocal set." % ip)
			return
		# Remove from the set.
		p = await asyncio.create_subprocess_exec(self.ipset,'del','netbanlocal',ip)
		r = await p.wait()
		assert r == 0, "Removing %s from netbanlocal set failed." % ip
		self.__logger.debug("%s removed from netbanlocal set." % ip)

	async def netban(self, cidr):
		"""Add a CIDR-notation net to the ban set."""
		self.__logger.debug("Received request to ban net %s." % cidr)
		p = await asyncio.create_subprocess_exec(self.ipset,'add','netbannet',cidr, stderr=PIPE)
		(stdout, stderr) = await p.communicate()
		try:
			assert p.returncode == 0, "Adding %s to netbannet set failed." % cidr
			self.__logger.debug("%s added to netbannet set." % cidr)
		except AssertionError as e:
			self.__logger.error("Error adding %s to set: %s" % (cidr, stderr))

	async def netunban(self, cidr):
		"""Remove a CIDR-notation net from the ban set."""
		self.__logger.debug("Received request to unban net %s." % cidr)
		# First, see if the net is in the set.
		self.__logger.debug("Finding netbannet set membership.")
		p = await asyncio.create_subprocess_exec(self.ipset,'list','netbannet', stdout=PIPE)
		(stdout, stderr) = await p.communicate()
		assert p.returncode == 0, "Error retrieving members of netbannet set."
		for line in stdout.decode('utf-8').split('\n'):
			if line == cidr:
				self.__logger.debug("Found %s in set; will remove." % cidr)
				break
		else:
			# This will execute if the cidr is not found (no break).
			self.__logger.warning("%s not in netbannet set." % cidr)
			return
		# Remove from the set.
		p = await asyncio.create_subprocess_exec(self.ipset,'del','netbannet',cidr)
		r = await p.wait()
		assert r == 0, "Removing %s from netbannet set failed." % cidr
		self.__logger.debug("%s removed from netbannet set." % cidr)
