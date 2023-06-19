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

def generate_pkts(pcap_name, flows, size):
	pktdump = PcapWriter(pcap_name, append=False)
	n_pkts = len(flows)

	src_mac = utils.random_mac()
	dst_mac = utils.random_mac()

	# Bypassing scapy's awfully slow wrpcap, have to use raw packets as input
	# To get a raw packet from a scapy packet use `bytes_encode(pkt)`.
	with PcapWriter(pcap_name, linktype=DLT_EN10MB) as pkt_wr:
		for i, flow in enumerate(flows):
			pkt = Ether(src=src_mac, dst=dst_mac)
			pkt = pkt/IP(src=flow["src_ip"], dst=flow["dst_ip"])
			pkt = pkt/UDP(sport=flow["src_port"], dport=flow["dst_port"])

			crc_size      = 4
			overhead      = len(pkt) + crc_size
			payload_size  = size - overhead
			payload       = "\x00" * payload_size
			pkt          /= payload

			raw_pkt       = bytes_encode(pkt)

			if not pkt_wr.header_present:
				pkt_wr._write_header(raw_pkt)
			pkt_wr._write_packet(raw_pkt)

			print(f"\r[*] Generating packets ({100 * (i+1) / n_pkts:3.2f} %) ...", end=" ")
		print(" done")

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
	generate_pkts(args.output, flows, args.size)

	elapsed = time.time() - start_time
	hr_elapsed = timedelta(seconds=elapsed)
	print(f"Execution time: {hr_elapsed}")
