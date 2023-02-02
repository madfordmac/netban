#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ipwhois.net import Net as ASNet
from ipwhois.asn import ASNOrigin, ASNOriginLookupError
from elasticsearch7 import AsyncElasticsearch
from elasticsearch7.exceptions import ConnectionTimeout as ESConnectionTimeout
from netaddr import IPSet, IPNetwork
import aiohttp
import asyncio
import logging

class NetBanNet(object):
	"""Use logs aggregated in an ELK stack to ban nets with poor policing."""

	def __init__(self, cfg, ban_manager):
		super(NetBanNet, self).__init__()
		self.__logger = logging.getLogger('netban.net')
		self.cfg = cfg
		self.ban_manager = ban_manager
		self.MAX_ES_RETRY = 3
		self.banned_as = {}
		self.ban_space = IPSet()
		self.limit = self.cfg.get_net_limit()
		self.interval = self.cfg.get_net_interval()
		self.retry_interval = self.cfg.get_net_retry_interval()
		self.es_host = self.cfg.get_elastic_host()
		self.es_index = self.cfg.get_elastic_index()
		self.__logger.debug("Will connect to Elasticsearch at <%s> and query the «%s» index." % (self.es_host, self.es_index))
		self.query = self.buildQuery()
		self.__logger.debug("Built Elasticsearch query: %r" % self.query)

	@classmethod
	async def create(cls, cfg, ban_manager):
		"""Factory method to create a running instance, since we need to await things."""
		n = NetBanNet(cfg, ban_manager)
		n.es = AsyncElasticsearch(n.es_host, timeout=60) # This is where the overall HTTP timeout is set.
		if not await n.es.ping(): # Creating the object doesn't actually try communication.
			n.__logger.error("Unable to connect to Elasticsearch at <%s>!" % n.es_host)
			raise EnvironmentError("Unable to connect to Elasticsearch!")
		await n.updateBanList()
		return n

	def buildQuery(self):
		"""Create the query that will be run against Elastic. Note that overall
		order is by document count, so an AS with a few IPs that hit often sort
		higher. However, NetBanLocalFile should prevent that from ever being
		too high. Trying to sort by the sub-aggregation order has high error in
		Elastic: https://www.elastic.co/guide/en/elasticsearch/reference/6.8/search-aggregations-bucket-terms-aggregation.html#search-aggregations-bucket-terms-aggregation-order"""
		return {
			"size": 0,
			"query": {
				"bool": {
					"filter": [
						{
							"term": {
								self.cfg.get_net_filter_field(): self.cfg.get_net_filter_term()
							}
						},
						{
							"range": {
								"@timestamp": {
									"gte": "now-%s" % self.cfg.get_net_query_distance(),
									"lte": "now"
								}
							}
						}
					]
				}
			},
			"aggs": {
				"as": {
					"terms": {
						"field": self.cfg.get_net_agg_field(),
						"size": self.cfg.get_net_buckets()
					},
					"aggs": {
						"n_ips": {
							"cardinality": {
								"field": self.cfg.get_net_count_field()
							}
						},
						"top_ip": {
							"top_hits": {
								"_source": {
									"includes": [self.cfg.get_net_count_field()]
								},
								"size": 1
							}
						}
					}
				}
			}
		}

	async def updateBanList(self):
		"""Pull new list of banned nets and update the set."""
		self.__logger.debug("Updating banned networks…")
		new_as = {}
		tries = 0
		result = {}
		while tries < self.MAX_ES_RETRY:
			try:
				result = await self.es.search(index=self.es_index, body=self.query)
				break
			except ESConnectionTimeout as e:
				self.__logger.warning("Timeout retrieving networks from Elastic, try %d." % tries)
				tries += 1
				await asyncio.sleep(30)
		else: # Only executed if we don't break out of loop.
			self.__logger.error("Failed to retrieve networks from Elastic after %d tries." % self.MAX_ES_RETRY)
			asyncio.get_running_loop().create_task(self.updateLater(self.retry_interval))
			return
		for bucket in result['aggregations']['as']['buckets']:
			if bucket['n_ips']['value'] > self.limit:
				asn = int(bucket['key'])
				topip = bucket['top_ip']['hits']['hits'][0]['_source']['asn']['ip']
				new_as[asn] = topip
		old_as_set = set(self.banned_as.keys())
		new_as_set = set(new_as.keys())
		as_to_drop = old_as_set - new_as_set
		as_to_add = new_as_set - old_as_set
		self.__logger.debug('Need to remove %d AS from ban set: %r' % (len(as_to_drop), as_to_drop))
		nets_to_drop = IPSet()
		for asn in as_to_drop:
			self.__logger.debug('Removing %d nets for AS%d' % (len(self.banned_as[asn]), asn))
			nets_to_drop.update([IPNetwork(n) for n in self.banned_as[asn]])
			for c in self.ban_space.intersection(self.banned_as[asn]).iter_cidrs():
				await self.ban_manager.netunban(str(c))
			del(self.banned_as[asn])
			self.ban_space = self.ban_space - nets_to_drop
		self.__logger.debug('Need to add %d AS to ban set: %r' % (len(as_to_add), as_to_add))
		for asn in as_to_add:
			topip = new_as[asn]
			try:
				asnets = ASNOrigin(ASNet(topip)).lookup('AS%d' % asn) # Wish I could await this line.
			except ASNOriginLookupError as e:
				self.__logger.warning('Unable to find nets for AS{asn:d} with base IP {ip:s}.'.format(asn=asn, ip=topip))
				self.__logger.warning('Message was: {err:s}'.format(err=str(e)))
				continue
			self.__logger.debug('Found {nnum:d} nets to ban for AS{asn:d} using base IP {ip:s}.'.format(asn=asn, ip=topip, nnum=len(asnets['nets'])))
			bans = [n['cidr'] for n in asnets['nets'] if n['cidr'].find(':') < 0]
			nets_to_ban = IPSet([IPNetwork(n) for n in bans])
			for c in (nets_to_ban - self.ban_space).iter_cidrs():
				await self.ban_manager.netban(str(c))
			self.banned_as[asn] = nets_to_ban
			self.ban_space.update(nets_to_ban)
		self.__logger.debug("Completed banned network update.")
		asyncio.get_running_loop().create_task(self.updateLater())

	async def updateLater(self, interval=-1):
		"""Wait for the configured interval and update the list again."""
		# Check if we should take the default value. Don't use variables in function definition because it has unexpected side effects.
		if interval == -1:
			interval = self.interval
		self.__logger.debug("Next banned network update in %d minutes." % int(interval / 60))
		await asyncio.sleep(interval)
		await self.updateBanList()
