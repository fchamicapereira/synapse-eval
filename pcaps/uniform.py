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

PARTITIONS_BASENAME = f".partition"

def random_mac(blacklist):
	mac = None
	while not mac or mac in blacklist:
		mac = f"02:00:00:{randint(0, 0xff):02x}:{randint(0, 0xff):02x}:{randint(0, 0xff):02x}"
	return mac

def internet_ip():
	def ip(msb_min, msb_max):
		b0 = randint(msb_min, msb_max)
		b1 = randint(0, 0xff)
		b2 = randint(0, 0xff)
		b3 = randint(0, 0xff)

		return f"{b0}.{b1}.{b2}.{b3}"

	public = [
		ip(11, 99),		# 11.0.0.0 – 99.255.255.255
		ip(101, 126),	# 101.0.0.0 – 126.255.255.255
		ip(128, 168),	# 128.0.0.0 – 168.255.255.255
		ip(170, 171),	# 170.0.0.0 – 171.255.255.255
		ip(173, 191),	# 173.0.0.0 – 191.255.255.255
		ip(193, 197),	# 193.0.0.0 – 197.255.255.255
		ip(199, 202),	# 199.0.0.0 – 202.255.255.255
	]

	return choice(public)

def ip_str_to_int(ip):
	d1, d2, d3, d4 = [ int(d) & 0xff for d in ip.split('.') ]
	return (d1 << 24) | (d2 << 16) | (d3 << 8) | (d4 << 0)

# e.g. subnet = 10.11.160.2/24
def random_ip_from_subnet(subnet):
	assert (len(subnet.split('/')) == 2)
	addr, mask = subnet.split('/')

	mask = int(mask)
	addr = ip_str_to_int(addr)

	mask_bits = ((2 ** mask) - 1) << (32 - mask)
	net = addr & mask_bits

	seed = random.randint(0, (2 ** (32 - mask)) - 1)
	addr = net | seed
	addr = socket.inet_ntoa(struct.pack('!L', addr))

	return addr

def __random_ip(private_only=False, internet_only=False, from_subnet=''):
	if from_subnet:
		return random_ip_from_subnet(from_subnet)

	if not private_only and not internet_only:
		chosen = socket.inet_ntoa(struct.pack('!L', random.randint(0,0xFFFFFFFF)))
		return chosen
	
	if internet_only:
		return internet_ip()
	
	def private_1():
		# 10.0.0.0/8
		return f"10.{randint(0, 0xff)}.{randint(0, 0xff)}.{randint(0, 0xff)}"
	def private_2():
		# 172.16.0.0/12
		return f"172.{randint(16, 0xff)}.{randint(0, 0xff)}.{randint(0, 0xff)}"
	def private_3():
		# 192.168.0.0/16
		return f"192.168.{randint(0, 0xff)}.{randint(0, 0xff)}"
	
	algos = [ private_1, private_2, private_3 ]
	chosen = choice(algos)()
	return chosen

def random_ip(blacklist, private_only=False, internet_only=False, from_subnet=''):
	ip = None
	while not ip or ip in blacklist:
		ip = __random_ip(private_only, internet_only, from_subnet)
	return ip

def random_port():
	return random.randint(1,10000)

def generate_n_unique_flows(nflows, opts):
	flows = []
	macs = []
	ips = []

	while len(flows) != nflows:
		src_mac = random_mac(macs)
		dst_mac = random_mac(macs)

		src_ip = random_ip(ips, opts['private_only'], opts['internet_only'], opts['from_subnet'])
		dst_ip = random_ip(ips, opts['private_only'], opts['internet_only'], opts['to_subnet'])

		src_port = random_port()
		dst_port = random_port()

		flow = {
			"src_mac": src_mac,
			"dst_mac": dst_mac,
			"src_ip": src_ip,
			"dst_ip": dst_ip,
			"src_port": src_port,
			"dst_port": dst_port,
		}

		macs += [ src_mac, dst_mac ]
		ips += [ src_ip, dst_ip ]

		flows.append(flow)
		
		print(f"\r[*] Generating flows ({100 * len(flows) / nflows:3.2f} %) ...", end=" ")
	print(" done")

	return flows

def generate_pkts(data):
	id = data[0]
	generated_pcap = data[1]
	flows = data[2]
	size = data[3]

	pktdump = PcapWriter(generated_pcap, append=False)
	n_pkts = len(flows)

	for i, flow in enumerate(flows):
		pkt = Ether(src=flow["src_mac"], dst=flow["dst_mac"])
		pkt = pkt/IP(src=flow["src_ip"], dst=flow["dst_ip"])
		pkt = pkt/UDP(sport=flow["src_port"], dport=flow["dst_port"])

		if len(pkt) - 14 < size:
			payload = "\x00" * (size - len(pkt))
			pkt = pkt/payload

		pktdump.write(pkt)

		if id == 0:
			print(f"\r[*] Generating packets ({100 * (i+1) / n_pkts:3.2f} %) ...", end=" ")
	if id == 0: print(" done")

if __name__ == "__main__":
	start_time = time.time()

	parser = argparse.ArgumentParser(description='Generate a pcap with uniform traffic.\n')

	parser.add_argument('--output',  help='output pcap', required=True)
	parser.add_argument('--flows', help='number of unique flows (>= 0)', type=int, required=True)
	parser.add_argument('--size', help='packet size ([64,1500])', type=int, required=True)
	parser.add_argument('--private-only', help='generate only flows on private networks', action='store_true', required=False)
	parser.add_argument('--internet-only', help='generate Internet only IPs', action='store_true', required=False)
	parser.add_argument('--from-subnet', help='src IPs from this subnet', type=str, required=False)
	parser.add_argument('--to-subnet', help='dst IPs from this subnet', type=str, required=False)

	args = parser.parse_args()

	output = Path(args.output)
	output_dir = output.parent
	output_filename = output.name
	assert(Path(output_dir).exists())

	assert args.flows > 0
	assert args.size >= 42 and args.size <= 1500

	cores = cpu_count()

	while args.flows % cores != 0:
		cores -= 1
	
	chunks_sz = int(args.flows / cores)

	opts = {
		'private_only':  args.private_only,
		'internet_only': args.internet_only,
		'from_subnet':   args.from_subnet,
		'to_subnet':     args.to_subnet,
	}

	flows = generate_n_unique_flows(args.flows, opts)

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
