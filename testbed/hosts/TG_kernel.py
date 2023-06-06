#!/usr/bin/env python3

from .Host import Host

import time
import os

BIND_KERNEL_SCRIPT = '/home/fcp/bind-e810-kernel.sh'

class TG_kernel(Host):
	def __init__(self, hostname, verbose=True):
		super().__init__('TG', hostname, verbose)

		# next, bind to kernel drivers
		self.exec(f'sudo {BIND_KERNEL_SCRIPT}', silence=True, must_succeed=False)
	
	def run(self, pcap, iface, duration):
		self.exec(f'sudo tcpreplay -K -i {iface} --duration={duration} -l 0 {pcap}', silence=True)