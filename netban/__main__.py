# -*- coding: utf-8 -*-
from . import NetBanConfig, NetBanManager
from .local import NetBanLocalFile
import asyncio
import argparse
import logging
from pprint import pprint
import sys, os

parser = argparse.ArgumentParser(description="Ban IPs trying to brute force logins. Watch local auth file and aggregate nets via Elasticsearch.")
parser.add_argument('config_file', help="Config file to read. Default: config.ini next to executable.", default=os.path.join(os.path.dirname(os.path.realpath(__file__)),'config.ini'))

async def main(args):
	# Set up logging
	logger = logging.getLogger('netban')
	logger.setLevel(logging.DEBUG)
	handlr = logging.StreamHandler()
	frmttr = logging.Formatter('%(asctime)s : %(name)s[%(process)d] : %(levelname)s :: %(message)s')
	if sys.stdout.isatty():
		handlr.setLevel(logging.DEBUG)
	else:
		handlr.setLevel(logging.ERROR)
	handlr.setFormatter(frmttr)
	logger.addHandler(handlr)

	# Set up main objects
	config = NetBanConfig(args.config_file)
	manager = NetBanManager(config)
	await manager.setup()
	local = await NetBanLocalFile.create(config, manager)

	await asyncio.sleep(5)
	pprint(asyncio.all_tasks())

	# Run
	#loop = asyncio.get_event_loop()
	#loop.wait()

if __name__ == '__main__':
	args = parser.parse_args()
	loop = asyncio.get_event_loop()
	loop.create_task(main(args))
	loop.run_forever()