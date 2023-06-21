#!/usr/bin/python3

import argparse
import time

from random import randint, sample, shuffle
from datetime import timedelta

from scapy.all import *
from scapy.utils import PcapWriter

from pathlib import Path

import utils

EPOCHS_IN_EXP_TIME = 1
MIN_EPOCHS         = 4 * EPOCHS_IN_EXP_TIME
MIN_PKT_SIZE_BYTES = 64
MAX_PKT_SIZE_BYTES = 1514

def get_pkts_in_time(t_sec, pkt_sz_bytes, rate_gbps):
	IPG      = 20
	CRC      = 4
	rate_bps = rate_gbps * 1e9
	pkts     = int(rate_bps * t_sec / ((pkt_sz_bytes + IPG + CRC) * 8))

	if pkts == 0:
		print("Epochs with 0 packets. Possible solutions:")
		print("  1. Increasing the rate")
		print("  2. Increasing the expiration time")
		print("  3. Reducing the packet size")
		exit(1)

	return pkts

def get_epoch_time(exp_time_sec):
	t_sec = exp_time_sec / EPOCHS_IN_EXP_TIME
	assert t_sec > 0
	return t_sec

def get_pkts_in_epoch(exp_time_sec, pkt_sz_bytes, rate_gbps):
	epoch_time_sec = get_epoch_time(exp_time_sec)
	epoch_pkts     = get_pkts_in_time(epoch_time_sec, pkt_sz_bytes, rate_gbps)
	return epoch_pkts

def churn_from_modified_flows(foreground_flows, epochs, epoch_time_sec):
	churn_fps  = foreground_flows / (epochs * epoch_time_sec)
	churn_fpm  = 60 * churn_fps
	return int(churn_fpm)

def print_report(data):
	s = ''
	s += f"Min churn         {data['min_churn']:,} fpm\n"
	s += f"Max churn         {data['max_churn']:,} fpm\n"
	s += f"Packet size       {data['pkt_sz']} bytes\n"
	s += f"Epochs            {data['epochs']:,}\n"
	s += f"Packets expired   {data['exp_pkts']:,}\n"
	s += f"Packets per epoch {data['pkts_epochs']:,}\n"
	s += f"Min rate          {data['min_rate']:.2f} Gbps\n"
	s += f"Target rate       {data['target_rate']:.2f} Gbps\n"
	s += f"Pcap size         {data['pcap_sz']:,} bytes\n"
	s += f"Background flows  {data['background_flows']:,}\n"
	s += f"Foreground flows  {data['foreground_flows']:,}\n"
	s += f"Total flows       {data['total_flows']:,}\n"

	print(s)

def save_report(data, report_filename):
	s = ''
	s += f"Min churn         {data['min_churn']:,} fpm\n"
	s += f"Max churn         {data['max_churn']:,} fpm\n"
	s += f"Packet size       {data['pkt_sz']} bytes\n"
	s += f"Epochs            {data['epochs']}\n"
	s += f"Packets expired   {data['exp_pkts']}\n"
	s += f"Packets per epoch {data['pkts_epochs']}\n"
	s += f"Min rate          {data['min_rate']:.2f} Gbps\n"
	s += f"Target rate       {data['target_rate']:.2f} Gbps\n"
	s += f"Pcap size         {data['pcap_sz']:,} bytes\n"
	s += f"Background flows  {data['background_flows']}\n"
	s += f"Foreground flows  {data['foreground_flows']}\n"
	s += f"Total flows       {data['total_flows']}\n"

	with open(report_filename, 'w') as f:
		f.write(s)

def get_required_number_of_epochs(exp_time_sec, churn_fpm, pkt_sz_bytes, rate_gbps):
	exp_tx_pkts    = get_pkts_in_time(exp_time_sec, pkt_sz_bytes, rate_gbps)
	epoch_time_sec = get_epoch_time(exp_time_sec)
	epoch_pkts     = get_pkts_in_epoch(exp_time_sec, pkt_sz_bytes, rate_gbps)
	
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

	report_data = {
		'min_churn':   min_churn_fpm,
		'max_churn':   max_churn_fpm,
		'pkt_sz':      pkt_sz_bytes,
		'epochs':      epochs,
		'exp_pkts':    exp_tx_pkts,
		'pkts_epochs': epoch_pkts,
		'target_rate': rate_gbps,
		'pcap_sz':     epochs * epoch_pkts * pkt_sz_bytes,
	}

	return epochs, report_data

def get_epochs_flows(churn_fpm, epochs, exp_time_sec, n_epoch_pkts, total_flows, private_only, internet_only, report):
	epoch_time_sec = get_epoch_time(exp_time_sec)

	assert epochs % 2 == 0

	n_modified_flows  = 0
	current_churn_fpm = 0

	while current_churn_fpm < churn_fpm:
		n_modified_flows += 1
		current_churn_fpm = churn_from_modified_flows(n_modified_flows, epochs, epoch_time_sec)

	assert n_modified_flows > 0 or churn_fpm == 0
	assert n_modified_flows <= n_epoch_pkts

	if total_flows == -1:
		total_flows = n_modified_flows

	if not (n_modified_flows <= total_flows <= n_epoch_pkts):
		print(f'Error: not enough flows')
		print(f'Requested {total_flows} total flows')
		print(f'Epoch flows: {n_epoch_pkts}')
		print(f'Foreground flows: {n_modified_flows}')
		print(f'Failed condition: foreground <= total <= epoch packets')
		exit(1)

	n_background_flows = total_flows - n_modified_flows
	n_padding_flows    = n_epoch_pkts - n_modified_flows - n_background_flows
	min_rate_gbps      = 1e-9 * n_modified_flows * (MIN_PKT_SIZE_BYTES*8) / exp_time_sec

	report['min_rate']         = min_rate_gbps
	report['background_flows'] = n_background_flows
	report['foreground_flows'] = n_modified_flows
	report['total_flows']      = total_flows

	old_flows        = utils.create_n_unique_flows(n_modified_flows, private_only, internet_only)
	new_flows        = utils.create_n_unique_flows(n_modified_flows, private_only, internet_only, old_flows)
	background_flows = utils.create_n_unique_flows(n_background_flows, private_only, internet_only, old_flows + new_flows)
	padding_flows    = [ f for f in old_flows for _ in range(int(n_padding_flows/n_modified_flows) + 1) ]
	padding_flows    = padding_flows[:n_padding_flows]
	translation      = {}

	shuffle(padding_flows)

	assert len(old_flows) + len(background_flows) + len(padding_flows) == n_epoch_pkts

	for old_flow, new_flow in zip(old_flows, new_flows):
		translation[utils.get_flow_id(old_flow)] = new_flow

	# list() for doing a deep copy
	epochs_flows = [ list(old_flows + background_flows + padding_flows) for _ in range(epochs) ]
	
	for epoch in range(int(epochs/2), epochs, 1):
		flows = epochs_flows[epoch]
		for i, flow in enumerate(flows):
			flow_id = utils.get_flow_id(flow)
			if flow_id in translation:
				epochs_flows[epoch][i] = translation[flow_id]
	
	return epochs_flows, current_churn_fpm

def generate_pkts(pcap_name, epochs_flows, size):
	total_pkts  = sum([ len(ef) for ef in epochs_flows ])
	generated   = 0
	encoded     = {}
	
	src_mac     = utils.random_mac()
	dst_mac     = utils.random_mac()

	# Bypassing scapy's awfully slow wrpcap, have to use raw packets as input
	# To get a raw packet from a scapy packet use `bytes_encode(pkt)`.
	with PcapWriter(pcap_name, linktype=DLT_EN10MB) as pkt_wr:
		for epoch_flows in epochs_flows:
			for flow in epoch_flows:
				flow_id = utils.get_flow_id(flow)

				if flow_id in encoded:
					raw_pkt = encoded[flow_id]
				else:
					pkt = Ether(src=src_mac, dst=dst_mac)
					pkt = pkt/IP(src=flow["src_ip"], dst=flow["dst_ip"])
					pkt = pkt/UDP(sport=flow["src_port"], dport=flow["dst_port"])

					crc_size      = 4
					overhead      = len(pkt) + crc_size
					payload_size  = size - overhead
					payload       = "\x00" * payload_size
					pkt          /= payload

					raw_pkt          = bytes_encode(pkt)
					encoded[flow_id] = raw_pkt 

				if not pkt_wr.header_present:
					pkt_wr._write_header(raw_pkt)
				pkt_wr._write_packet(raw_pkt)

				generated += 1
				progress   = 100 * generated / total_pkts
				print(f"{utils.VT100_ERASE_LINE}Generating packets {progress:3.2f} %", end=" ")
		print()

if __name__ == "__main__":
	start_time = time.time()

	parser = argparse.ArgumentParser(description='Generate a pcap with uniform traffic.\n')

	parser.add_argument('--expiration', type=int, required=True,
						help='expiration time in us (>= 1us)')

	parser.add_argument('--churn', type=int, required=True,
						help='churn in fpm (>= 1)')
	
	parser.add_argument('--rate', type=float, required=True, default=100,
						help='rate in Gbps')

	parser.add_argument('--size', type=int, required=True,
						help=f'packet size ([{MIN_PKT_SIZE_BYTES},{MAX_PKT_SIZE_BYTES}])')
	
	parser.add_argument('--total-flows', type=int, default=-1,
						help=f'total number of flows (background + foreground)')

	parser.add_argument('--private-only', action='store_true', required=False,
						help='generate only flows on private networks')

	parser.add_argument('--internet-only', action='store_true', required=False,
						help='generate Internet only IPs')

	args = parser.parse_args()

	assert args.size >= MIN_PKT_SIZE_BYTES and args.size <= MAX_PKT_SIZE_BYTES
	assert args.expiration >= 1
	assert args.churn >= 0

	exp_time_sec        = args.expiration * 1e-6
	epoch_pkts          = get_pkts_in_epoch(exp_time_sec, args.size, args.rate)
	epochs, report      = get_required_number_of_epochs(exp_time_sec, args.churn, args.size, args.rate)
	epochs_flows, churn = get_epochs_flows(
		args.churn, epochs, exp_time_sec, epoch_pkts, args.total_flows,
		args.private_only, args.internet_only, report)

	rate_str = int(args.rate) if int(args.rate) == args.rate else str(args.rate).replace('.','_')

	output_fname = f'churn_{churn}_fpm_{args.size}B_{args.expiration}us_{rate_str}_Gbps.pcap'
	report_fname = f'churn_{churn}_fpm_{args.size}B_{args.expiration}us_{rate_str}_Gbps.dat'

	print(f"Out:    {output_fname}")
	print(f"Report: {report_fname}")
	print()

	print_report(report)
	generate_pkts(output_fname, epochs_flows, args.size)

	save_report(report, report_fname)

	elapsed = time.time() - start_time
	hr_elapsed = timedelta(seconds=elapsed)
	print(f"Execution time: {hr_elapsed}")
