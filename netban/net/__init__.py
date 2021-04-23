#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ipwhois.net import Net as ASNet
from ipwhois.asn import ASNOrigin
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
		self.limit = self.cfg.get_net_limit()
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
		new_bans = set()
		async with aiohttp.ClientSession() as session:
			result = {}
			async with session.post(self.query_uri, json=self.query) as response:
				assert response.status == 200, "Received %(status)d error response from Elastic: %(body)s" % {'status': response.status, 'body': response.text()}
				result = response.json()
			for bucket in result['aggregations']['as']['buckets']:
				if bucket['n_ips']['value'] > self.limit:
					asn = int(bucket['key'])
					topip = bucket['top_ip']['hits']['hits'][0]['_source']['asn']['ip']
					asnets = ASNOrigin(ASNet(topip)).lookup('AS%d' % asn) # Wish I could await this line.
					self.__logger.debug('Found {nnum:d} nets to ban for AS{asn:d} using base IP {ip:s}.'.format(asn=asn, ip=topip, nnum=len(asnets['nets'])))
					new_bans.update(set([n['cidr'] for n in asnets['nets']]))
		cidr_to_drop = self.ban_set - new_bans
		cidr_to_add = new_bans - self.ban_set
		self.__logger('Need to remove %d nets from ban set: %r' % (len(cidr_to_drop), cidr_to_drop))
		self.__logger('Need to add %d nets to ban set: %r' % (len(cidr_to_add), cidr_to_add))
		


