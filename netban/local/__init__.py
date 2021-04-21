#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pyinotify
import re
import aioredis
import asyncio
import logging
import os

class NetBanLocalFile(object):
	"""Watch the local file with your auth logs for failed attempts"""
	def __init__(self, cfg, ban_manager):
		super(NetBanLocalFile, self).__init__()
		self.__logger = logging.getLogger('netban.localfile')
		self.cfg = cfg
		self.ban_manager = ban_manager
		self.fail_re = re.compile(r'Failed password for( invalid user)? \w+ from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
		self.last_offset = -1

	@classmethod
	async def create(cls, cfg, ban_manager):
		"""Factory method to create a running instance, since we need to await things."""
		l = NetBanLocalFile(cfg, ban_manager)
		l.wm = pyinotify.WatchManager()
		l.mask = pyinotify.IN_CREATE | pyinotify.IN_MODIFY
		l.notifier = pyinotify.AsyncioNotifier(l.wm, asyncio.get_event_loop(), callback=l.callback)
		l.file_to_watch = cfg.get_local_file()
		l.last_offset = os.stat(l.file_to_watch).st_size
		l.wdd = l.wm.add_watch(l.file_to_watch, l.mask, rec=False)
		l.__logger.info("Created new async iNotifier to watch <%s>." % l.file_to_watch)
		l.redis_db_num = cfg.get_redis_db()
		l.r = await aioredis.create_redis('redis://localhost/%d' % l.redis_db_num) # https://stackoverflow.com/questions/33128325/how-to-set-class-attribute-with-await-in-init
		await l.r.config_set('notify-keyspace-events', 'Ex')
		l.__logger.info("Created new connection to redis database %d." % l.redis_db_num)
		asyncio.ensure_future(l.processExpiry())
		l.__logger.info("Created future to handle IP ban expiry.")
		return l

	def callback(self, notifier):
		asyncio.get_event_loop().create_task(self.processUpdate())

	async def processExpiry(self):
		"""Subscribe to redis keyspace expiry events to remove the IP."""
		# Connections handling a subscription can't do other work.
		r_sub = await aioredis.create_redis('redis://localhost/%d' % self.redis_db_num)
		self.__logger.debug("Created new redis connection to handle expiry subscription.")
		res = await r_sub.subscribe('__keyevent@%d__:expired' % self.redis_db_num)
		chan = res[0]
		while await chan.wait_message():
			self.__logger.debug("Received new expiry notification.")
			await self.ban_manager.unban(chan.get())

	async def processUpdate(self):
		"""Scheduled by callback when there is a new event on the
		watched file to process the new lines."""
		self.__logger.debug("New invocation of processUpdate().")
		size = os.stat(self.file_to_watch).st_size
		if size == self.last_offset:
			self.__logger.debug("New file size equal to last offset; nothing to do.")
			return
		else:
			self.__logger.debug(f"Last offset at {self.last_offset:d}; file now {size:d}.")
		lines = []
		with open(self.file_to_watch, 'r') as logfile:
			if size > self.last_offset:
				self.__logger.debug(f"Seeking to {self.last_offset:d} bytes.")
				logfile.seek(self.last_offset)
			lines = logfile.readlines()
			self.__logger.debug("Read %d new lines." % len(lines))
			self.last_offset = logfile.tell()
			self.__logger.debug(f"Offset updated to {self.last_offset:d}.")
		for line in lines:
			m = self.fail_re.search(line)
			if m:
				self.__logger.debug(f"Line matched failure pattern: {line:s}")
				ip = m.group('ip')
				ban = await self.evaluateIp(ip)
				if ban:
					await self.ban_manager.ban(ip)
		return True

	async def evaluateIp(self, ip):
		"""Determine if an IP has had enough hits to ban it."""
		n = await self.r.incr(ip)
		await self.r.expire(ip, self.cfg.get_ip_timeout())
		self.__logger.debug(f"Login failure {n:d} for {ip:s}.")
		return n >= self.cfg.get_ip_limit()
