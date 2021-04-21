#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
		self.ban_set = set()
		self.query_uri = self.cfg.get_elastic_uri()
		self.__logger.debug("Will query Elasticsearch at <%s>." % self.query_uri)
		self.query = self.build_query()
		self.__logger.debug("Built Elasticsearch query: %r" % self.query)

	@classmethod
	async def create(cls, cfg, ban_manager):
		"""Factory method to create a running instance, since we need to await things."""
		n = NetBanNet(cfg, ban_manager)
		await n.updateBanList()
		return n

	def buildQuery(self):
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
						"size": self.cfg.get_net_limit()
					},
					"aggs": {
						"n_ips": {
							"cardinality": {
								"field": self.cfg.get_net_count_field()
							}
						}
					}
				}
			}
		}

	async def updateBanList(self):
		"""Pull new list of banned nets and update the set."""
		result = {}
		async with aiohttp.ClientSession() as session:
			async with session.post(self.query_uri, json=self.query) as response:
				assert response.status == 200, "Received %(status)d error response from Elastic: %(body)s" % {'status': response.status, 'body': response.text()}
				result = response.json()
