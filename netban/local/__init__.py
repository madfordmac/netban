#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pyinotify
import re
import redis.asyncio as redis
import asyncio
import logging
import os

class NetBanLocalFile(object):
	"""Watch the local file with your auth logs for failed attempts"""

	class NetBanLocalEventHandler(pyinotify.ProcessEvent):
		"""pyinotify.ProcessEvent subclass to handle the inotify events from this module."""
		def __init__(self, nblf):
			self.nblf = nblf
			self.__logger = logging.getLogger('netban.localevth')
			self.loop = asyncio.get_running_loop()
			self.__logger.info("Created event handler for iNotify events.")

		def process_IN_CREATE(self, event):
			if event.pathname == self.nblf.file_to_watch:
				self.loop.create_task(self.nblf.processReset())

		def process_IN_MODIFY(self, event):
			if event.pathname == self.nblf.file_to_watch:
				self.loop.create_task(self.nblf.processUpdate())

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
		l.update_lock = asyncio.Lock()
		l.wm = pyinotify.WatchManager()
		l.mask = pyinotify.IN_CREATE | pyinotify.IN_MODIFY
		l.notifier = pyinotify.AsyncioNotifier(l.wm, asyncio.get_event_loop(), default_proc_fun=l.NetBanLocalEventHandler(l))
		l.file_to_watch = cfg.get_local_file()
		l.last_offset = os.stat(l.file_to_watch).st_size
		l.wdd = l.wm.add_watch(os.path.dirname(l.file_to_watch), l.mask, rec=False)
		l.__logger.info("Created new async iNotifier to watch <%s>." % l.file_to_watch)
		l.redis_db_num = cfg.get_redis_db()
		l.r = redis.from_url('redis://127.0.0.1/%d' % l.redis_db_num)
		await l.r.config_set('notify-keyspace-events', 'Ex')
		l.__logger.info("Created new connection to redis database %d." % l.redis_db_num)
		asyncio.ensure_future(l.processExpiry())
		l.__logger.info("Created future to handle IP ban expiry.")
		return l

	async def processExpiry(self):
		"""Subscribe to redis keyspace expiry events to remove the IP."""
		# Connections handling a subscription can't do other work.
		r_sub = redis.from_url('redis://127.0.0.1/%d' % self.redis_db_num)
		self.__logger.debug("Created new redis connection to handle expiry subscription.")
		chan = r_sub.pubsub()
		await chan.subscribe('__keyevent@%d__:expired' % self.redis_db_num)
		self.__logger.debug("Subscribed to redis key expirations.")
		while True:
			message = await chan.get_message(ignore_subscribe_messages=True)
			if message is None:
				continue
			self.__logger.debug("Received new expiry notification.")
			ip = message['data']
			ip = ip.decode('ascii')
			self.__logger.info("%s is expiring." % ip)
			await self.ban_manager.unban(ip)

	async def processUpdate(self):
		"""Scheduled by iNotify WatchManager when there is a modify event on the
		watched file to process the new lines."""
		self.__logger.debug("New invocation of processUpdate().")
		lines = []
		async with self.update_lock:
			self.__logger.debug("Acquired file reading lock.")
			size = os.stat(self.file_to_watch).st_size
			if size == self.last_offset:
				self.__logger.debug("New file size equal to last offset; nothing to do.")
				return
			else:
				self.__logger.debug("Last offset at %(last_offset)d; file now %(size)d." % {'last_offset': self.last_offset, 'size': size})
			with open(self.file_to_watch, 'r') as logfile:
				if size > self.last_offset:
					self.__logger.debug("Seeking to %d bytes." % self.last_offset)
					logfile.seek(self.last_offset)
				lines = logfile.readlines()
				self.__logger.debug("Read %d new lines." % len(lines))
				self.last_offset = logfile.tell()
				self.__logger.debug("Offset updated to %d." % self.last_offset)
		self.__logger.debug("Released file reading lock.")
		for line in lines:
			m = self.fail_re.search(line)
			if m:
				self.__logger.debug("Line matched failure pattern: %s" % line.strip())
				ip = m.group('ip')
				ban = await self.evaluateIp(ip)
				if ban:
					await self.ban_manager.ban(ip)
		return True

	async def processReset(self):
		"""Scheduled by iNotify WatchManager when there is a create event on the
		watched file to reset the internal state."""
		self.__logger.debug("New invocation of processReset().")
		async with self.update_lock:
			self.size = 0

	async def evaluateIp(self, ip):
		"""Determine if an IP has had enough hits to ban it."""
		n = await self.r.incr(ip)
		await self.r.expire(ip, self.cfg.get_ip_timeout())
		self.__logger.info("Login failure %(n)d for %(ip)s." % {'n': n, 'ip': ip})
		return n >= self.cfg.get_ip_limit()
