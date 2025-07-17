#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import configparser
import logging
import asyncio
import os
from subprocess import PIPE
from shlex import split as shplit

class NetBanConfig(object):
	"""Loads the config from file"""
	def __init__(self, config_file_name):
		super(NetBanConfig, self).__init__()
		self.__logger = logging.getLogger('netban.config')
		cfg = configparser.ConfigParser()
		cfg.read(config_file_name)
		self.__logger.info("Read and parsed config file <%s>." % config_file_name)
		self.cfg = cfg
	
	def get_debug(self):
		"""Convenience method for getting the debug flag."""
		return self.cfg['general'].getboolean('debug')

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

	def get_local_set_name(self):
		"""Convenience function for getting the local nftables set name."""
		return shplit(self.cfg['local'].get('set-name'))

	def get_net_set_name(self):
		"""Convenience function for getting the net nftables set name."""
		return shplit(self.cfg['net'].get('set-name'))

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
		self.nft = self.whichNft()
		self.__logger.debug("Using nft from %s" % self.nft)
		# Check configured sets exist
		for set_name in (self.cfg.get_local_set_name(), self.cfg.get_net_set_name()):
			p = await asyncio.create_subprocess_exec(self.nft,'list','set', *set_name)
			r = await p.wait()
			if r != 0:
				self.__logger.critical("Failed to list set %s. Does it exist?" % ' '.join(set_name))
				raise SystemExit(-1)
		self.__logger.debug("Confirmed sets exist.")

		self.initialized = True

	@classmethod
	def whichNft(cls):
		"""Find an executable version of nft."""
		for nft in ('/usr/sbin/nft', '/sbin/nft'):
			if os.path.exists(nft) and os.access(nft, os.X_OK):
				return nft
		raise EnvironmentError('No executable `nft` command found.')

	async def __ban(self, ip, nftset):
		"""Do the heavy lifting of banning an ip or cidr."""
		self.__logger.debug("Received request to ban ip %s." % ip)
		p = await asyncio.create_subprocess_exec(self.nft,'add','element',*nftset,'{',ip,'}')
		r = await p.wait()
		if r != 0:
			self.__logger.error("Adding %s to set failed." % ip)
		else:
			self.__logger.info("%s successfully banned." % ip)

	async def __unban(self, ip, nftset):
		"""Do the heavy lifting of unbanning an ip or cidr."""
		self.__logger.debug("Received request to unban ip %s." % ip)
		# First, see if the IP is in the set.
		self.__logger.debug("Finding set membership.")
		p = await asyncio.create_subprocess_exec(self.nft,'list','set',*nftset, stdout=PIPE)
		(stdout, stderr) = await p.communicate()
		if p.returncode != 0:
			self.__logger.error("Error retrieving members of set. Cannot unban %s." % ip)
			return
		for line in stdout.decode('utf-8').split('\n'):
			if ip in line:
				self.__logger.debug("Found %s in set; will remove." % ip)
				break
		else:
			# This will execute if the IP is not found (no break).
			self.__logger.warning("%s not in set." % ip)
			return
		# Remove from the set.
		p = await asyncio.create_subprocess_exec(self.nft,'delete','element',*nftset,'{',ip,'}')
		r = await p.wait()
		if r != 0:
			self.__logger.error("Removing %s from set failed." % ip)
		else:
			self.__logger.info("%s successfully unbanned." % ip)
	
	async def ban(self, ip):
		"""Add a single IP address to the ban set."""
		localset = self.cfg.get_local_set_name()
		await self.__ban(ip, localset)

	async def unban(self, ip):
		"""Unban a single IP address from the ban set."""
		localset = self.cfg.get_local_set_name()
		await self.__unban(ip, localset)

	async def netban(self, cidr):
		"""Add a CIDR-notation net to the ban set."""
		netset = self.cfg.get_net_set_name()
		await self.__ban(cidr, netset)

	async def netunban(self, cidr):
		"""Remove a CIDR-notation net from the ban set."""
		netset = self.cfg.get_net_set_name()
		await self.__unban(cidr, netset)
