#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pyinotify
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
		self.wm = pyinotify.WatchManager()
		self.mask = pyinotify.IN_CREATE | pyinotify.IN_MODIFY
		self.fail_re = re.compile(r'Failed password for( invalid user)? \w+ from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
		self.last_offset = -1
		self.notifier = pyinotify.AsyncNotifier(self.wm, NetBanLocalEventHandler(self))
		self.file_to_watch = cfg.get_local_file()
		self.last_offset = os.stat(self.file_to_watch).st_size
		self.wdd = wm.add_watch(self.file_to_watch, self.mask, rec=False)
		self.__logger.info("Created new async iNotifier to watch <%s>." % self.file_to_watch)
		redis_db_num = cfg.get_redis_db()
		self.r = aioredis.create_redis('redis://localhost/%d' % redis_db_num)
		self.r.config_set('notify-keyspace-events', 'Ex')
		self.__logger.info("Created new connection to redis database %d." % redis_db_num)
		asyncio.ensure_future(self.processExpiry())
		self.__logger.info("Created future to handle IP ban expiry.")

	async def processExpiry(self):
		"""Subscribe to redis keyspace expiry events to remove the IP."""
		res = await self.r.subscribe('__keyevent@%d__:expired' % self.cfg.get_redis_db())
		chan = res[0]
		while await chan.wait_message():
			await self.ban_manager.unban(chan.get())

	def processUpdate(self):
		"""Called by NetBanLocalEventHandler when there is a new event on the
		watched file to process the new lines."""
		size = os.stat(self.file_to_watch).st_size
		if size == self.last_offset:
			return
		lines = []
		with open(self.file_to_watch, 'r') as logfile:
			if size > self.last_offset:
				logfile.seek(self.last_offset)
			lines = logfile.readlines()
			self.last_offset = logfile.tell()
		for line in lines:
			m = self.fail_re.search(line)
			if m:
				ip = m.group('ip')
				ban = await self.evaluateIp(ip)
				if ban:
					await self.ban_manager.ban(ip)
		return True

	async def evaluateIp(self, ip):
		"""Determine if an IP has had enough hits to ban it."""
		n = await self.r.incr(ip)
		await self.r.expire(ip, self.cfg.get_ip_timeout())
		return n >= self.cfg.get_ip_limit()


class NetBanLocalEventHandler(pyinotify.ProcessEvent):
	"""Event Handler for file updates. Since we do te same thing for all events,
	implement the default method.
	"""
	def __init__(self, nblf):
		super(NetBanLocalEventHandler, self).__init__()
		self.nblf = nblf

	def process_default(self, event):
		self.nblf.processUpdate()
