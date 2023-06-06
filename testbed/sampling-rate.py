#!/usr/bin/env python3

from hosts.Tofino import Tofino
from hosts.Dispatcher import Dispatcher
from hosts.KitNet import KitNet
from hosts.TG_DPDK import TG_DPDK

import util
import hosts
import os
import argparse
import glob

import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt

SCRIPT_DIR        = os.path.dirname(os.path.realpath(__file__))
TEST_RESULTS_DIR  = f'{SCRIPT_DIR}/results/sampling-rate'
PLOT_PPS          = f'{TEST_RESULTS_DIR}/sampling-rate-pps.png'
PLOT_BPS          = f'{TEST_RESULTS_DIR}/sampling-rate-bps.png'
VERBOSE           = False

MIN_SAMPLING_RATE_DEFAULT = 1024
MAX_SAMPLING_RATE_DEFAULT = 65536

def get_data():
	data_files_pattern = f'{TEST_RESULTS_DIR}/*.csv'
	data_files = glob.glob(data_files_pattern)
	
	data = {}

	for data_file in data_files:
		basename = os.path.basename(data_file)
		attack   = os.path.splitext(basename)[0]

		data[attack] = []

		with open(data_file, 'r') as f:
			lines = f.readlines()

			for line in lines:
				if line and line[0] == '#':
					continue

				line = line.rstrip().split(',')
				assert len(line) == 5

				sampling_rate = int(line[0])
				tg_rate       = float(line[1])
				rx_rate_bps   = int(line[2])
				rx_rate_pps   = int(line[3])
				tx_rate_pps   = int(line[4])

				data[attack].append((sampling_rate,tg_rate,rx_rate_bps,rx_rate_pps,tx_rate_pps))
		
	return data

def get_sampling_rate_range(data):
	min_sampling_rate = -1
	max_sampling_rate = -1
	
	for attack in data.keys():
		for values in data[attack]:
			sampling_rate = values[0]
			min_sampling_rate = min(min_sampling_rate, sampling_rate)
			max_sampling_rate = max(max_sampling_rate, sampling_rate)
	
	return min_sampling_rate, max_sampling_rate

def gen_plot(data, plot_file, pps=False, bps=False):
	assert pps or bps

	fig = plt.figure()
	plt.clf()

	ax = fig.add_subplot(111)
	ax.set_aspect(1)

	min_sampling_rate, max_sampling_rate = get_sampling_rate_range(data)

	if bps:
		vmin = 0
		vmax = int(100e9)
		units = 'bps'
	else:
		vmin = 0
		vmax = int(50e6)
		units = 'pps'
	
	attacks        = sorted(list(data.keys()))
	sampling_rates = []
	matrix         = [ [] for _ in range(len(attacks)) ]

	for i, attack in enumerate(attacks):
		attack_vector = data[attack]
		attack_vector.sort(key=lambda v: v[0])

		for sampling_rate,tg_rate,rx_rate_bps,rx_rate_pps,tx_rate_pps in attack_vector:
			if pps: matrix[i].append(rx_rate_pps)
			else:   matrix[i].append(rx_rate_bps)

			sampling_rates = list(set(sampling_rates + [ sampling_rate ]))

	# print('Sampling rates', sampling_rates)
	# print('Attacks', attacks)

	# colormap = plt.cm.jet
	colormap = mpl.colormaps['RdYlGn']
	
	nodes  = [ 0.0, 0.5, 1.0 ]
	colors = [ 'crimson', 'yellow', 'mediumseagreen' ]
	cmap   = mpl.colors.LinearSegmentedColormap.from_list("mycmap", list(zip(nodes, colors)))
	cmap.set_under('black')

	res = ax.imshow(matrix, cmap=cmap, vmin=vmin, vmax=vmax, interpolation='nearest', aspect='auto')

	for x in range(len(matrix)):
		for y in range(len(matrix[x])):
			v = matrix[x][y]
			ax.annotate(f'{util.compact(v, no_decimal=True)}{units}', xy=(y,x), va='center', ha='center')

	n_ticks = 6
	ticks = []
	labels = []
	for i in range(n_ticks):
		tick = int(vmax*i/(n_ticks-1))
		ticks.append(tick)
		labels.append(f'{util.compact(tick, no_decimal=True)}{units}')

	cbar = fig.colorbar(res, ticks=ticks)
	cbar.ax.set_yticklabels(labels)

	width  = len(sampling_rates)
	height = len(attacks)

	plt.xticks(range(width), sampling_rates)
	plt.yticks(range(height), attacks)

	plt.savefig(plot_file, bbox_inches='tight')
	# plt.show()

def plot():
	data = get_data()

	if not data:
		print('No data.')
		exit(0)

	print('Generating pps plot')
	gen_plot(data, PLOT_PPS, pps=True)

	print('Generating bps plot')
	gen_plot(data, PLOT_BPS, bps=True)

	print('Done')

def run_benchmarks(min_sampling_rate, max_sampling_rate, target_attack=None):
	testbed = util.get_testbed_cfg()
	tests   = util.get_tests()

	target_tests = [ t for t in tests if not target_attack or target_attack == t['attack'] ]

	if not target_tests:
		print(f'No attack named \"{target_attack}\".')
		exit(0)

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

	sampling_rate = min_sampling_rate
	results = {}

	while sampling_rate <= max_sampling_rate:
		print(f'[*] installing for {sampling_rate} sampling...')

		tofino.modify_sampling_rate(sampling_rate)
		tofino.install()

		for test in target_tests:
			attack = test['attack']
			print(f"[*] attack={attack} sampling_rate={sampling_rate}")

			rate, rx_rate_bps, rx_rate_pps, tx_rate_pps = util.find_stable_throughput(
				tofino, dispatcher, kitnet, tg_dpdk, testbed, test)
			
			if attack not in results:
				results[attack] = []
			
			results[attack].append((sampling_rate, rate, rx_rate_bps, rx_rate_pps, tx_rate_pps))

		sampling_rate *= 2
	
	for attack in results.keys():
		report_file = f'{TEST_RESULTS_DIR}/{attack}.csv'
		with open(report_file, 'w') as f:
			f.write(f'# sampling rate,tg rate (%),rx rate (bps),rx rate (pps),tx rate (pps)\n')

			for sampling_rate, rate, rx_rate_bps, rx_rate_pps, tx_rate_pps in results[attack]:
				f.write(f'{sampling_rate},{rate},{rx_rate_bps},{rx_rate_pps},{tx_rate_pps}\n')

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	
	parser.add_argument('--attack',
		type=str,
		required=False,
		help='Target attack'
	)
	
	parser.add_argument('--skip-bench',
		required=False,
		action='store_true',
		help='Skip benchmarks'
	)

	parser.add_argument('--skip-plot',
		required=False,
		action='store_true',
		help='Skip plot'
	)

	parser.add_argument('--min-sampling',
		type=int,
		required=False,
		default=MIN_SAMPLING_RATE_DEFAULT,
		help=f'Min sampling rate value (default={MIN_SAMPLING_RATE_DEFAULT})'
	)

	parser.add_argument('--max-sampling',
		type=int,
		required=False,
		default=MAX_SAMPLING_RATE_DEFAULT,
		help=f'Max sampling rate value (default={MAX_SAMPLING_RATE_DEFAULT})'
	)

	args = parser.parse_args()

	if not os.path.exists(TEST_RESULTS_DIR):
		os.makedirs(TEST_RESULTS_DIR)

	if not args.skip_bench:
		run_benchmarks(args.min_sampling, args.max_sampling, args.attack)

	if not args.skip_plot:
		plot()