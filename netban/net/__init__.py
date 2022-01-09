#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ipwhois.net import Net as ASNet
from ipwhois.asn import ASNOrigin
from elasticsearch7 import AsyncElasticsearch
from elasticsearch7.exceptions import ConnectionTimeout as ESConnectionTimeout
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
		self.ban_set = set()
		self.limit = self.cfg.get_net_limit()
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
		new_bans = set()
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
			asyncio.get_running_loop().create_task(self.updateLater(600))
			return
		for bucket in result['aggregations']['as']['buckets']:
			if bucket['n_ips']['value'] > self.limit:
				asn = int(bucket['key'])
				topip = bucket['top_ip']['hits']['hits'][0]['_source']['asn']['ip']
				asnets = ASNOrigin(ASNet(topip)).lookup('AS%d' % asn) # Wish I could await this line.
				self.__logger.debug('Found {nnum:d} nets to ban for AS{asn:d} using base IP {ip:s}.'.format(asn=asn, ip=topip, nnum=len(asnets['nets'])))
				new_bans.update(set([n['cidr'] for n in asnets['nets'] if n['cidr'].find(':') < 0]))
		cidr_to_drop = self.ban_set - new_bans
		cidr_to_add = new_bans - self.ban_set
		self.__logger.debug('Need to remove %d nets from ban set: %r' % (len(cidr_to_drop), cidr_to_drop))
		self.__logger.debug('Need to add %d nets to ban set: %r' % (len(cidr_to_add), cidr_to_add))
		for c in cidr_to_drop:
			await self.ban_manager.netunban(c)
		for c in cidr_to_add:
			await self.ban_manager.netban(c)
		self.__logger.debug("Completed banned network update.")
		asyncio.get_running_loop().create_task(self.updateLater())

	async def updateLater(self, interval=3600):
		"""Wait for the configured interval and update the list again."""
		self.__logger.debug("Next banned network update in %d minutes." % int(interval / 60))
		await asyncio.sleep(interval)
		await self.updateBanList()
