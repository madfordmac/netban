# -*- coding: utf-8 -*-
from . import NetBanConfig, NetBanManager
from .local import NetBanLocalFile
import asyncio
import argparse
import logging
import os

parser = argparse.ArgumentParser(description="Ban IPs trying to brute force logins. Watch local auth file and aggregate nets via Elasticsearch.")
parser.add_argument('config_file', help="Config file to read. Default: config.ini next to executable.", default=os.path.join(os.path.dirname(os.path.realpath(__file__)),'config.ini'))

async def main(args):
	config = NetBanConfig(args.config_file)
	manager = NetBanManager(config)
	local = NetBanLocalFile(config, manager)

	# Run
	loop = asyncio.get_event_loop()
	loop.run_forever()

if __name__ == '__main__':
	args = parser.parse_args()
	asyncio.run(main(args))