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
		p = await asyncio.create_subprocess_exec('/usr/sbin/ipset','create','netbannet','hash:net')
		r = await p.wait()
		assert r == 0, "Creation of netbannet set failed."
		# Add sets to iptables 
		insert_at = self.cfg.get_rule_number()
		p = await asyncio.create_subprocess_exec('/usr/sbin/iptables','-I','INPUT',f'{insert_at:d}','-m','set','--match-set','netbanlocal','src','-j','DROP')
		r = await p.wait()
		assert r == 0, "Inserting netbanlocal rule failed."
		p = await asyncio.create_subprocess_exec('/usr/sbin/iptables','-I','INPUT',f'{insert_at:d}','-m','set','--match-set','netbannet','src','-j','DROP')
		r = await p.wait()
		assert r == 0, "Inserting netbannet rule failed."

	async def ban(ip):
		"""Add an IP address to the ban set."""
		p = await asyncio.create_subprocess_exec('/usr/sbin/ipset','add','netbanlocal',ip)
		r = await p.wait()
		assert r == 0, "Adding %s to netbanlocal set failed." % ip

	async def unban(ip):
		"""Remove an IP address from the ban set."""
		p = await asyncio.create_subprocess_exec('/usr/sbin/ipset','del','netbanlocal',ip)
		r = await p.wait()
		assert r == 0, "Removing %s from netbanlocal set failed." % ip

	async def netban(cidr):
		"""Add a CIDR-notation net to the ban set."""
		p = await asyncio.create_subprocess_exec('/usr/sbin/ipset','add','netbannet',cidr)
		r = await p.wait()
		assert r == 0, "Adding %s to netbannet set failed." % cidr

	async def netunban(cidr):
		"""Remove a CIDR-notation net from the ban set."""
		p = await asyncio.create_subprocess_exec('/usr/sbin/ipset','del','netbannet',cidr)
		r = await p.wait()
		assert r == 0, "Removing %s from netbannet set failed." % cidr