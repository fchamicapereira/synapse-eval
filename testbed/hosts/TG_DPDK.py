#!/usr/bin/env python3

from .Host import Host

import time
import os

BIND_DPDK_SCRIPT = '/home/fcp/bind-igb_uio.sh'
PKTGEN_DIR       = '/opt/Pktgen-DPDK'
PKTGEN_EXE_NAME  = 'pktgen'
RESULTS_FILENAME = 'results.tsv'
NUM_TX_CORES     = 4

PKTGEN_SCRIPT_NAME     = 'replay.lua'
PKTGEN_SCRIPT_TEMPLATE = \
"""
package.path = package.path ..";?.lua;test/?.lua;app/?.lua;../?.lua"

require "Pktgen";

local duration_ms   = {{duration_ms}};
local delay_time_ms = 1000;
local sendport      = "{{port}}";
local rate          = {{rate}};

function main()
    pktgen.screen("off");
    pktgen.clr();

    pktgen.set(sendport, "rate", rate);

    pktgen.start(sendport);
    pktgen.delay(duration_ms);
    pktgen.stop(sendport);
    pktgen.delay(delay_time_ms);
    
    pktgen.quit();
end

main();
"""

class TG_DPDK(Host):
	def __init__(self, hostname, verbose=True):
		super().__init__('TG', hostname, verbose)

		if not self.has_directory(PKTGEN_DIR):
			self.err(f'Pktgen directory not found: {PKTGEN_DIR}')
		
		# Stop any instances running before running our own
		self.stop()

		# next, bind to DPDK drivers
		self.exec(f'sudo {BIND_DPDK_SCRIPT}', silence=True, must_succeed=False)
	
	def run(self, pcap, tx_port, rate, duration_seconds):
		if not self.has_file(pcap):
			self.err(f'File not found: {pcap}')

		script_file  = f"{PKTGEN_DIR}/scripts/{PKTGEN_SCRIPT_NAME}"

		script = PKTGEN_SCRIPT_TEMPLATE
		script = script.replace('{{duration_ms}}', str(duration_seconds * 1000))
		script = script.replace('{{port}}', str(tx_port))
		script = script.replace('{{rate}}', str(rate))

		self.exec(f'cat <<EOT > {script_file}\n{script}EOT', silence=True)

		tx_cores = "16" if NUM_TX_CORES == 1 else f"16-{16 + (NUM_TX_CORES - 1)}"

		cmd = [
			"sudo", "-E",
			f"{PKTGEN_DIR}/Builddir/app/pktgen",
			"-l", "0,16-31", "-n", "4", "--proc-type", "auto",
			"--",
			"-N", "-T", "-P",
			"-m", f"[31:{tx_cores}].{tx_port}",
			"-s", f"{tx_port}:{pcap}",
			"-f", f"{script_file}",
		]

		self.exec(" ".join(cmd), path=PKTGEN_DIR, silence=True)
	
	def stop(self):
		self.kill(PKTGEN_EXE_NAME)
