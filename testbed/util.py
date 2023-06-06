#!/usr/bin/env python3

import os
import shutil
import json

SCRIPT_DIR   = os.path.dirname(os.path.realpath(__file__))
TESTBED_JSON = f'{SCRIPT_DIR}/testbed.json'
TESTS_JSON   = f'{SCRIPT_DIR}/tests.json'

DURATION_SECONDS     = 10
MAX_RETRIES          = 5
SEARCH_ITERATIONS    = 10
RATE_LOWER_THRESHOLD = 0.1
LOSS_THRESHOLD       = 0.001

def get_testbed_cfg():
	with open(TESTBED_JSON, 'r') as f:
		testbed = json.load(f)
		return testbed

def get_tests():
	with open(TESTS_JSON, 'r') as f:
		tests = json.load(f)
		return tests['tests']

def get_test(attack):
	data  = None
	tests = get_tests()

	for test in tests:
		if attack == test['attack']:
			data = test
			break

	if not data:
		print(f'Error: attack {attack} not found in {TESTS_JSON}')
		exit(1)
	
	return data

def compact(n, no_decimal=False):
	orders = [
		(1e9, 1e9, 'G'),
		(1e6, 1e6, 'M'),
		(1e3, 1e3, 'K'),
		(0, 1, ''),
	]

	for o in orders:
		if n >= o[0]:
			if no_decimal:
				return f'{int(n/o[1])}{o[2]}'
			else:
				return f'{n/o[1]:.1f}{o[2]}'
	
	return n
	
def get_data_from_controller(controller_report_file):
	with open(controller_report_file, 'r') as f:
		lines = f.readlines()
		assert(len(lines) > 1)

		ports_info = lines[1:]
		stats_port = int(ports_info[-1].split('\t')[0])

		total_rx_bytes   = -1
		total_rx_pkts    = -1
		total_tx_samples = -1

		for port_info in ports_info:
			port_info = port_info.split('\t')
			port      = int(port_info[0])
			rx_bytes  = int(port_info[1])
			rx_pkts   = int(port_info[2])
			tx_pkts   = int(port_info[3])

			if port != stats_port:
				total_rx_pkts  += rx_pkts
				total_rx_bytes += rx_bytes
			else:
				total_tx_samples = tx_pkts
				if total_rx_pkts > 0 and total_tx_samples > 0:
					return total_rx_bytes,total_rx_pkts,total_tx_samples
				else:
					return -1,-1,-1
		return total_rx_bytes,total_rx_pkts,total_tx_samples

def get_processed_samples_from_dispatcher(dispatcher_report_file):
	with open(dispatcher_report_file, 'r') as f:
		lines = f.readlines()
		samples = lines[1:]
		return len(samples)

def run(tofino, dispatcher, kitnet, tg_dpdk, testbed, test, rate):
	controller_report_file = None
	dispatcher_report_file = None

	rx_pkts    = -1
	rx_bytes   = -1
	tx_samples = -1
	processed  = -1
	loss       = -1

	success = False
	try_run = 0
	while not success:
		try_run += 1

		if try_run > MAX_RETRIES:
			print('Maximum number of allowed retries reached. Exiting.')
			exit(1)

		tofino.start()
		dispatcher.start(testbed['dispatcher']['listen-iface'])

		kitnet.start(
			f"{testbed['plugins']['kitnet']['models']}/{test['models']['fm']}",
			f"{testbed['plugins']['kitnet']['models']}/{test['models']['el']}",
			f"{testbed['plugins']['kitnet']['models']}/{test['models']['ol']}",
			f"{testbed['plugins']['kitnet']['models']}/{test['models']['ts']}",
		)

		pcap    = f"{testbed['tg']['pcaps']}/{test['pcap']}"
		tx_port = testbed['tg']['tx-dpdk-port']

		tg_dpdk.run(pcap, tx_port, rate, DURATION_SECONDS)

		tofino.stop()
		dispatcher.stop()
		kitnet.stop()

		controller_report_file = tofino.get_report()
		dispatcher_report_file = dispatcher.get_report()

		rx_bytes,rx_pkts,tx_samples = get_data_from_controller(controller_report_file)

		processed = get_processed_samples_from_dispatcher(dispatcher_report_file)
		loss      = abs(tx_samples - processed) / tx_samples
		success   = rx_pkts > -1 and tx_samples > -1

		if not success:
			print(f"  - Packets not flowing through Tofino. Repeating experiment.")

		elif processed > tx_samples:
			print(f"  WARNING: too many samples received (tx {tx_samples} | samples {processed}")
		
	assert rx_pkts > 0
	assert tx_samples > 0

	os.remove(controller_report_file)
	os.remove(dispatcher_report_file)

	rx_rate_pps = int(rx_pkts / DURATION_SECONDS)
	rx_rate_bps = int((rx_bytes * 8) / DURATION_SECONDS)
	tx_rate_pps = int(tx_samples / DURATION_SECONDS)

	return rx_rate_bps, rx_rate_pps, tx_rate_pps, loss

def find_stable_throughput(tofino, dispatcher, kitnet, tg_dpdk, testbed, test, verbose=True):
	upper_bound = 100.0
	lower_bound = 0
	i           = 0

	max_rate = upper_bound
	mid_rate = upper_bound
	min_rate = lower_bound

	best_rate        = -1
	best_rx_rate_pps = -1
	best_rx_rate_bps = -1
	best_tx_rate_pps = -1
	best_loss        = -1

	while True:
		rate = mid_rate

		if rate < RATE_LOWER_THRESHOLD or i >= SEARCH_ITERATIONS:
			break
		
		rx_rate_bps, rx_rate_pps, tx_rate_pps, loss = run(tofino, dispatcher, kitnet, tg_dpdk, testbed, test, rate)

		if verbose:
			msg  = '  '
			msg += f'[{i+1:2d}/{SEARCH_ITERATIONS}] '
			msg += f'rate {rate:3.2f}% '
			msg += f'rx {compact(rx_rate_pps, no_decimal=True)}pps '
			msg += f'({compact(rx_rate_bps, no_decimal=True)}bps) '
			msg += f'tx {compact(tx_rate_pps, no_decimal=True)}pps '
			msg += f'loss {100 * loss:.2f}%'

			print(msg)

		if loss < LOSS_THRESHOLD:
			if tx_rate_pps > best_tx_rate_pps:
				best_rate        = rate
				best_rx_rate_pps = rx_rate_pps
				best_rx_rate_bps = rx_rate_bps
				best_tx_rate_pps = tx_rate_pps
				best_loss        = loss

			if mid_rate == upper_bound or i + 1 >= SEARCH_ITERATIONS:
				break

			min_rate = mid_rate
			mid_rate = mid_rate + (max_rate - mid_rate) / 2
		else:
			max_rate = mid_rate
			mid_rate = min_rate + (mid_rate - min_rate) / 2
		
		i += 1
	
	if verbose:
		msg  = '  '
		msg += f'Best rate '
		msg += f'rate {best_rate:3.2f}% '
		msg += f'rx {compact(best_rx_rate_pps, no_decimal=True)}pps '
		msg += f'({compact(best_rx_rate_bps, no_decimal=True)}bps) '
		msg += f'tx {compact(best_tx_rate_pps, no_decimal=True)}pps '
		msg += f'loss {100 * best_loss:.2f}%'

		print(msg)

	return best_rate, best_rx_rate_bps, best_rx_rate_pps, best_tx_rate_pps