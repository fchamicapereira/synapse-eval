#!/usr/bin/env python3

import os
import time

from .Host import Host
from .Dispatcher import Dispatcher
from .KitNet import KitNet
from .TG_kernel import TG_kernel

SCRIPT_DIR             = os.path.dirname(os.path.realpath(__file__))

CONTROLLER_EXE_NAME    = 'peregrine-controller'

CONTROLLER_LOG_FILE    = '/tmp/run-with-hw.log'
CONTROLLER_READY_MSG   = 'Peregrine controller is ready.'
CONTROLLER_REPORT_FILE = 'peregrine-controller.tsv'
CONTROLLER_TICK_FILE   = 'controller-tick.csv'
CONTROLLER_TIMEOUT     = 10 # seconds

TICK_PROBE_INTEVAL     = 1  # second.

CPU_USAGE_SCRIPT = 'get_process_cpu_ticks.py'
LOCAL_CPU_USAGE_SCRIPT_PATH = f'{SCRIPT_DIR}/../../util/{CPU_USAGE_SCRIPT}'

class Tofino(Host):
	def __init__(self, hostname, peregrine_path, verbose=True):
		super().__init__('tofino', hostname, verbose)

		self.peregrine_path      = peregrine_path
		self.controller_path     = f'{self.peregrine_path}/controller'
		self.p4_path             = f'{self.peregrine_path}/p4'
		self.controller_exe_path = f'{self.controller_path}/build/{CONTROLLER_EXE_NAME}'

		self.pid = None

		if not self.has_directory(self.peregrine_path):
			self.err(f'Directory not found: {self.peregrine_path}')

		if not self.has_directory(self.controller_path):
			self.err(f'Directory not found: {self.controller_path}')

		if not self.has_directory(self.p4_path):
			self.err(f'Directory not found: {self.p4_path}')

		# Stop any instances running before running our own
		self.stop()
	
	def install(self):
		self.exec('make install', path=self.p4_path, silence=True)
	
	def start(self):
		# Compiling first
		self.exec('make release -j', path=self.controller_path, silence=True)

		self.exec(f'./run-with-hw.sh > {CONTROLLER_LOG_FILE} 2>&1',
			path=self.controller_path, background=True)
		
		# Get PID.
		ret, out, err = self.exec(
			f'pgrep {CONTROLLER_EXE_NAME}', capture_output=True)

		if out is None:
			self.log('ERROR: Fail to obtain controller PID.')
			exit(1)
		
		# Check if there are multiple instances running.
		pids = out.split('\n')

		if len(pids) == 0:
			self.log('ERROR: Controller not running.')
			exit(1)

		if len(pids) > 2:
			self.log('ERROR: Multiple instances of controller running.')
			exit(1)
		
		self.pid = pids[0]

		self.send_files(LOCAL_CPU_USAGE_SCRIPT_PATH, self.peregrine_path)

		script_path = f'{self.controller_path}/{CPU_USAGE_SCRIPT}'
		out_file = f'{self.controller_path}/{CONTROLLER_TICK_FILE}'
		self.exec(
			f'{script_path} {self.pid} --interval {TICK_PROBE_INTEVAL} > '
			f'{out_file}', background=True)
		
		start = time.time()

		while 1:
			time.sleep(1)

			ret, out, err = self.exec(f'cat {CONTROLLER_LOG_FILE}', capture_output=True)
			elapsed = (time.time() - start)

			if not self.is_program_running(self.controller_exe_path) and elapsed > CONTROLLER_TIMEOUT:
				self.log('ERROR: Controller not running.')
				self.log('Dumping of log file:')
				print(out)
				exit(1)

			if CONTROLLER_READY_MSG in out:
				break
	
	def modify_sampling_rate(self, sampling_rate):
		sed_cmd = f'sed -E -i \'s/#define SAMPLING [0-9]+/#define SAMPLING {sampling_rate}/g\''
		target = f'{self.p4_path}/includes/constants.p4'
		self.exec(f'{sed_cmd} {target}')
	
	def stop(self):
		self.kill(CONTROLLER_EXE_NAME)
		self.kill(CPU_USAGE_SCRIPT)
		self.exec(f'rm -f {CONTROLLER_LOG_FILE} || true', must_succeed=False)

	def get_report(self):
		return self.get_files(f'{self.controller_path}/{CONTROLLER_REPORT_FILE}')
	
	def get_tick_report(self):
		return self.get_files(f'{self.controller_path}/{CONTROLLER_TICK_FILE}')

if __name__ == '__main__':
	tofino     = Tofino('tofino', '/root/peregrine')
	dispatcher = Dispatcher('gsd+e291427x1300274', '/home/fcp/peregrine')
	kitnet     = KitNet('gsd+e291427x1300274', '/home/fcp/peregrine')
	tg         = TG_kernel('gsd+e291427x1300275')
