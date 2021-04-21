#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import aiohttp
import asyncio
import logging

class NetBanNet(object):
	"""Use logs aggregated in an ELK stack to ban nets with poor policing."""
	
	# This is the json structure for the Elasticsearch query
	AS_QUERY = {
		"size": 0,
		"query": {
			"bool": {
				"filter": [
					{
						"term": {
							"ssh_action": "Failed"
						}
					},
					{
						"range": {
							"@timestamp": {
								"gte": "now-7d",
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
					"field": "asn.asn",
					"size": 10
				},
				"aggs": {
					"n_ips": {
						"cardinality": {
							"field": "asn.ip"
						}
					}
				}
			}
		}
	}

	def __init__(self, cfg, ban_manager):
		super(NetBanNet, self).__init__()
		self.__logger = logging.getLogger('netban.net')
		self.cfg = cfg
		self.ban_manager = ban_manager
		self.ban_set = set()

	@classmethod
	async def create(cls, cfg, ban_manager):
		"""Factory method to create a running instance, since we need to await things."""
		n = NetBanNet(cfg, ban_manager)
		await n.updateBanList()
		return n

	async def updateBanList(self):
		"""Pull new list of banned nets and update the set."""
		async with aiohttp.ClientSession() as session:
			async with session.post(self.query_url, json=self.AS_QUERY) as result:
				pass