#!/usr/bin/python3

import argparse
import time
import re

from random import randint
from datetime import timedelta

from scapy.all import *
from scapy.utils import PcapWriter

from multiprocessing import Pool, cpu_count, current_process
from subprocess import call
from pathlib import Path
from math import ceil, floor

from statistics import mean, stdev
from collections import Counter

import utils

def generate_pkts(data):
	id = data[0]
	generated_pcap = data[1]
	flows = data[2]
	size = data[3]

	pktdump = PcapWriter(generated_pcap, append=False)
	n_pkts = len(flows)

	src_mac = utils.random_mac()
	dst_mac = utils.random_mac()

	for i, flow in enumerate(flows):
		pkt = Ether(src=src_mac, dst=dst_mac)
		pkt = pkt/IP(src=flow["src_ip"], dst=flow["dst_ip"])
		pkt = pkt/UDP(sport=flow["src_port"], dport=flow["dst_port"])

		crc_size      = 4
		overhead      = len(pkt) + crc_size
		payload_size  = size - overhead
		payload       = "\x00" * payload_size
		pkt          /= payload

		pktdump.write(pkt)

		if id == 0:
			print(f"\r[*] Generating packets ({100 * (i+1) / n_pkts:3.2f} %) ...", end=" ")
	if id == 0: print(" done")

if __name__ == "__main__":
	start_time = time.time()

	parser = argparse.ArgumentParser(description='Generate a pcap with uniform traffic.\n')

	parser.add_argument('--output',  help='output pcap', required=True)
	parser.add_argument('--flows', help='number of unique flows (>= 0)', type=int, required=True)
	parser.add_argument('--size', help='packet size ([64,1514])', type=int, required=True)
	parser.add_argument('--private-only', help='generate only flows on private networks', action='store_true', required=False)
	parser.add_argument('--internet-only', help='generate Internet only IPs', action='store_true', required=False)

	args = parser.parse_args()

	output = Path(args.output)
	output_dir = output.parent
	output_filename = output.name
	assert(Path(output_dir).exists())

	assert args.flows > 0
	assert args.size >= 64 and args.size <= 1514

	cores = cpu_count()

	while args.flows % cores != 0:
		cores -= 1
	
	chunks_sz = int(args.flows / cores)

	flows = utils.create_n_unique_flows(args.flows, args.private_only, args.internet_only)

	print(f"[*] Using {cores} cores ({int(args.flows / cores)} pkts/core)")
	pool = Pool(cores)

	data = []
	generated_pcaps = []
	
	for id, x in enumerate(range(0, args.flows, chunks_sz)):
		generated_pcap = f"{output_dir}/.{output_filename}.{id}"
		chunk = flows[x:x+chunks_sz]

		generated_pcaps.append(generated_pcap)
		data.append((id, generated_pcap, chunk, args.size))

	pool.map(generate_pkts, data)

	call([ "mergecap", "-F", "pcap", "-w", f"{args.output}" ] + generated_pcaps)
	call([ "rm" ] + generated_pcaps)

	elapsed = time.time() - start_time
	hr_elapsed = timedelta(seconds=elapsed)
	print(f"Execution time: {hr_elapsed}")
