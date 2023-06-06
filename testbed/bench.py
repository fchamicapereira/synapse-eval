#!/usr/bin/env python3

from hosts.Tofino import Tofino
from hosts.Dispatcher import Dispatcher
from hosts.KitNet import KitNet
from hosts.TG_DPDK import TG_DPDK

import util
import hosts
import os
import argparse

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
VERBOSE    = False

if __name__ == '__main__':
	parser = argparse.ArgumentParser(prog='bench')
	parser.add_argument('attack', type=str, help='Target attack')	
	parser.add_argument('sampling', type=int, help='Target sampling rate')

	args = parser.parse_args()

	testbed = util.get_testbed_cfg()
	test    = util.get_test(args.attack)

	tofino = Tofino(
		hostname=testbed['tofino']['hostname'],
		peregrine_path=testbed['tofino']['peregrine-path'],
		verbose=VERBOSE
	)
	
	dispatcher = Dispatcher(
		hostname=testbed['dispatcher']['hostname'],
		peregrine_path=testbed['dispatcher']['peregrine-path'],
		verbose=VERBOSE
	)

	kitnet = KitNet(
		hostname=testbed['plugins']['kitnet']['hostname'],
		peregrine_path=testbed['plugins']['kitnet']['peregrine-path'],
		verbose=VERBOSE
	)

	tg_dpdk = TG_DPDK(
		hostname=testbed['tg']['hostname'],
		verbose=VERBOSE
	)

	print(f'[*] Installing...')
	tofino.modify_sampling_rate(args.sampling)
	tofino.install()

	print(f"[*] attack={test['attack']} sampling_rate={args.sampling}")
	util.find_stable_throughput(tofino, dispatcher, kitnet, tg_dpdk, testbed, test)
