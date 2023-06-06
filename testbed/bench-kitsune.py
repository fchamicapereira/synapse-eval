#!/usr/bin/env python3

import util
import hosts
import os
import argparse
import subprocess
import statistics

SCRIPT_DIR           = os.path.dirname(os.path.realpath(__file__))
TEST_RESULTS_DIR     = f'{SCRIPT_DIR}/results/kitsune'
TEST_RESULTS         = f'{TEST_RESULTS_DIR}/results.csv'
TEST_STATS           = f'{TEST_RESULTS_DIR}/stats.csv'
KITSUNE_DIR          = f'{SCRIPT_DIR}/../sota/kitsune'
KITSUNE_BENCH_SCRIPT = f'{KITSUNE_DIR}/bench.sh'

def run_benchmarks(attacks, pcaps_dir):
	results = []

	for attack in attacks:
		pcap = f"{pcaps_dir}/{attack['pcap']}"
		assert '.pcap' in pcap
		name = attack['attack']

		pcap_basename = pcap.split('/')[-1].split('.pcap')[0]
		csv           = f"{TEST_RESULTS_DIR}/{pcap_basename}.csv"

		print(f"[*] attack={name}")

		cmd = [ KITSUNE_BENCH_SCRIPT, pcap ]

		proc = subprocess.run(cmd,
			cwd=TEST_RESULTS_DIR,
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL
		)

		assert proc.returncode == 0

		with open(csv, 'r') as f:
			lines = f.readlines()
			assert len(lines) >= 1
			
			line = lines[0].rstrip('\n')
			line = line.split(',')

			training_time  = line[0]
			execution_time = line[1]
			dt_fe          = line[2]
			dt_ad          = line[3]
			pps            = int(line[4])
			bps            = int(line[5])

			results.append((name, training_time, execution_time,dt_fe, dt_ad, pps, bps))
			print(f"      rate {util.compact(int(pps))}pps {util.compact(int(bps))}bps")

		os.remove(csv)
	
	with open(TEST_RESULTS, 'w') as f:
		for result in results:
			f.write(f'{",".join(str(r) for r in result)}\n')

def dump_stats():
	ppss = []
	bpss = []

	with open(TEST_RESULTS, 'r') as f:
		lines = f.readlines()
		for line in lines:
			line = line.rstrip('\n')
			line = line.split(',')

			if not line: continue

			attack         = line[0]
			training_time  = line[1]
			execution_time = line[2]
			dt_fe          = line[3]
			dt_ad          = line[4]
			pps            = int(line[5])
			bps            = int(line[6])

			ppss.append(pps)
			bpss.append(bps)

	with open(TEST_STATS, 'w') as f:
		if len(ppss) == 1:
			pps_m     = ppss[0]
			pps_mean  = int(ppss[0])
			pps_stdev = int(0)
			pps_M     = ppss[0]

			bps_m     = bpss[0]
			bps_mean  = int(bpss[0])
			bps_stdev = int(0)
			bps_M     = bpss[0]
		else:
			pps_m     = min(ppss)
			pps_mean  = int(statistics.mean(ppss))
			pps_stdev = int(statistics.stdev(ppss))
			pps_M     = max(ppss)

			bps_m     = min(bpss)
			bps_mean  = int(statistics.mean(bpss))
			bps_stdev = int(statistics.stdev(bpss))
			bps_M     = max(bpss)

		f.write(f"{pps_m},{pps_mean},{pps_stdev},{pps_M},")
		f.write(f"{bps_m},{bps_mean},{bps_stdev},{bps_M}")
		f.write(f"\n")

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Benchmark Kitsune')

	parser.add_argument('--attack', type=str, required=False, help='Target attack')
	parser.add_argument('--pcaps-dir', type=str, required=False, default=SCRIPT_DIR, help='Path to pcaps')

	parser.add_argument('--skip-bench',
		required=False,
		action='store_true',
		help='Skip benchmarks'
	)

	args = parser.parse_args()

	tests        = util.get_tests()
	target_tests = [ t for t in tests if not args.attack or args.attack == t['attack'] ]

	if not os.path.exists(TEST_RESULTS_DIR):
		os.makedirs(TEST_RESULTS_DIR)
	
	if not args.skip_bench:
		run_benchmarks(target_tests, args.pcaps_dir)
	
	dump_stats()