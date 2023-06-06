#!/usr/bin/python3

import argparse
import time

from random import randint, sample
from datetime import timedelta

from scapy.all import *
from scapy.utils import PcapWriter

from pathlib import Path

# MAX_RATE         = 100 # 100 Gbps
MAX_RATE           = 50  # 60 Gbps for 64B packets
EPOCHS_IN_EXP_TIME = 10
MIN_EPOCHS         = 4 * EPOCHS_IN_EXP_TIME
MIN_PKT_SIZE_BYTES = 64
MAX_PKT_SIZE_BYTES = 1500

def random_mac():
	return f"02:00:00:{randint(0, 0xff):02x}:{randint(0, 0xff):02x}:{randint(0, 0xff):02x}"

def is_multicast(ip):
	# 224.0.0.0 => 239.255.255.255
	assert isinstance(ip, str)
	b0, b1, b2, b3 = [ int(b) for b in ip.split('.') ]
	return 224 <= b0 <= 239

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

def random_ip(private_only=False, internet_only=False):
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

def random_port():
	return random.randint(1,10000)

def get_flow_id(flow):
    if "src_mac" in flow and "dst_mac" in flow:
        return f"""
            {flow['src_mac']}::
            {flow['dst_mac']}::
            {flow['src_ip']}::
            {flow['dst_ip']}::
            {flow['src_port']}::
            {flow['dst_port']}
        """.replace(" ", "").replace("\n", "")

    return f"""
            {flow['src_ip']}::
            {flow['dst_ip']}::
            {flow['src_port']}::
            {flow['dst_port']}
        """.replace(" ", "").replace("\n", "")

def create_flow(private_only, internet_only):
	src_mac = random_mac()
	dst_mac = random_mac()

	flow = {
		"src_mac": src_mac,
		"dst_mac": dst_mac,
		"src_ip": random_ip(private_only, internet_only),
		"dst_ip": random_ip(private_only, internet_only),
		"src_port": random_port(),
		"dst_port": random_port(),
	}

	return flow

def create_n_unique_flows(nflows, private_only, internet_only, flows_exception=[]):
	flows = []

	while len(flows) < nflows:
		flow = create_flow(private_only, internet_only)
		if flow not in flows and flow not in flows_exception:
			flows.append(flow)
		print(f"\rUnique flows: {len(flows):,}/{nflows:,}", end='')
	print()
	
	return flows

def get_pkts_in_time(t_sec, pkt_sz_bytes):
	IPG          = 24
	max_rate_bps = MAX_RATE * 1e9
	pkts         = int(max_rate_bps * t_sec / ((pkt_sz_bytes + IPG) * 8))
	assert pkts > 0
	return pkts

def get_epoch_time(exp_time_sec):
	t_sec = exp_time_sec / EPOCHS_IN_EXP_TIME
	assert t_sec > 0
	return t_sec

def get_pkts_in_epoch(exp_time_sec, pkt_sz_bytes):
	epoch_time_sec = get_epoch_time(exp_time_sec)
	epoch_pkts     = get_pkts_in_time(epoch_time_sec, pkt_sz_bytes)
	return epoch_pkts

def churn_from_modified_flows(modified_flows, epochs, epoch_time_sec):
	churn_fps = modified_flows / (epochs * epoch_time_sec)
	churn_fpm = 60 * churn_fps
	return int(churn_fpm)

def get_required_number_of_epochs(exp_time_sec, churn_fpm, pkt_sz_bytes):
	exp_tx_pkts    = get_pkts_in_time(exp_time_sec, pkt_sz_bytes)
	epoch_time_sec = get_epoch_time(exp_time_sec)
	epoch_pkts     = get_pkts_in_epoch(exp_time_sec, pkt_sz_bytes)
	
	epochs         = MIN_EPOCHS
	min_churn_fpm  = churn_from_modified_flows(1, epochs, epoch_time_sec)
	max_churn_fpm  = churn_from_modified_flows(epoch_pkts, epochs, epoch_time_sec)

	if max_churn_fpm < churn_fpm:
		print(f'Max churn: {max_churn_fpm:,} fpm')
		print(f'Requested: {churn_fpm:,} fpm')
		exit(1)

	while churn_fpm > 0 and not min_churn_fpm <= churn_fpm <= max_churn_fpm:
		epochs       += 2
		min_churn_fpm = churn_from_modified_flows(1, epochs, epoch_time_sec)
		max_churn_fpm = churn_from_modified_flows(epoch_pkts, epochs, epoch_time_sec)

		assert max_churn_fpm >= min_churn_fpm

	min_rate_gbps = 1e-9 * epoch_pkts * MIN_PKT_SIZE_BYTES * 8 / exp_time_sec

	print(f"min churn   {min_churn_fpm:,} fpm")
	print(f"max churn   {max_churn_fpm:,} fpm")
	print(f"pkt_sz      {pkt_sz_bytes} bytes")
	print(f"epochs      {epochs}")
	print(f"exp pkts    {exp_tx_pkts}")
	print(f"pkts epochs {epoch_pkts}")
	print(f"min rate    {min_rate_gbps:.2f} Gbps")
	print(f"target rate {MAX_RATE:.2f} Gbps")
	print(f"pcap sz     {epochs * epoch_pkts * pkt_sz_bytes:,} bytes")

	return epochs

def get_epochs_flows(epoch_flows, churn_fpm, epochs, exp_time_sec, private_only, internet_only):
	epoch_time_sec = get_epoch_time(exp_time_sec)

	assert epochs % 2 == 0

	n_modified_flows  = 0
	current_churn_fpm = 0

	while current_churn_fpm < churn_fpm:
		n_modified_flows += 1
		current_churn_fpm = churn_from_modified_flows(n_modified_flows, epochs, epoch_time_sec)

	assert n_modified_flows > 0 or churn_fpm == 0
	assert n_modified_flows <= len(epoch_flows)

	print(f"requested   {churn_fpm:,} fpm")
	print(f"obtained    {current_churn_fpm:,} fpm")

	modified_flows = sample(epoch_flows, n_modified_flows)
	new_flows      = create_n_unique_flows(n_modified_flows, private_only, internet_only, epoch_flows)
	translation    = {}

	for old_flow, new_flow in zip(modified_flows, new_flows):
		translation[get_flow_id(old_flow)] = new_flow

	epochs_flows = [ list(epoch_flows) for _ in range(epochs) ]
	
	for epoch in range(int(epochs/2), epochs, 1):
		flows = epochs_flows[epoch]
		for i, flow in enumerate(flows):
			flow_id = get_flow_id(flow)
			if flow_id in translation:
				epochs_flows[epoch][i] = translation[flow_id]
	
	return epochs_flows, current_churn_fpm

def generate_pkts(pcap, epochs_flows, size):
	pktdump = PcapWriter(pcap, append=False)
	total_pkts = sum([ len(ef) for ef in epochs_flows ])
	generated = 0

	for epoch_flows in epochs_flows:
		for flow in epoch_flows:
			pkt = Ether(src=flow["src_mac"], dst=flow["dst_mac"])
			pkt = pkt/IP(src=flow["src_ip"], dst=flow["dst_ip"])
			pkt = pkt/UDP(sport=flow["src_port"], dport=flow["dst_port"])

			if len(pkt) - 14 < size:
				payload = "\x00" * (size - len(pkt))
				pkt = pkt/payload

			pktdump.write(pkt)

			generated += 1
			print(f"\rGenerating packets {100 * generated / total_pkts:3.2f} %", end=" ")
	print()
if __name__ == "__main__":
	start_time = time.time()

	parser = argparse.ArgumentParser(description='Generate a pcap with uniform traffic.\n')

	parser.add_argument('--expiration', type=int, required=True,
						help='expiration time in us (>= 1us)')

	parser.add_argument('--churn', type=int, required=True,
						help='churn in fpm (>= 1)')

	parser.add_argument('--size', type=int, required=True,
						help=f'packet size ([{MIN_PKT_SIZE_BYTES},{MAX_PKT_SIZE_BYTES}])')

	parser.add_argument('--private-only', action='store_true', required=False,
						help='generate only flows on private networks')

	parser.add_argument('--internet-only', action='store_true', required=False,
						help='generate Internet only IPs')

	args = parser.parse_args()

	assert args.size >= MIN_PKT_SIZE_BYTES and args.size <= MAX_PKT_SIZE_BYTES
	assert args.expiration >= 1
	assert args.churn >= 0

	exp_time_sec        = args.expiration * 1e-6
	epoch_pkts          = get_pkts_in_epoch(exp_time_sec, args.size)
	epoch_flows         = create_n_unique_flows(epoch_pkts, args.private_only, args.internet_only)
	epochs              = get_required_number_of_epochs(exp_time_sec, args.churn, args.size)
	epochs_flows, churn = get_epochs_flows(epoch_flows, args.churn, epochs, exp_time_sec, args.private_only, args.internet_only)

	output = f'churn_{churn}_fpm_{args.size}B_{args.expiration}us_{MAX_RATE}_Gbps.pcap'
	print(f"out         {output}")

	generate_pkts(output, epochs_flows, args.size)

	elapsed = time.time() - start_time
	hr_elapsed = timedelta(seconds=elapsed)
	print(f"Execution time: {hr_elapsed}")
