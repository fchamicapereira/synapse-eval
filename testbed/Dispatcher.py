#!/usr/bin/env python3

from .Host import Host

import time
import os

DISPATCHER_EXE_NAME    = 'dispatcher'

DISPATCHER_LOG_FILE    = '/tmp/dispatcher.log'
DISPATCHER_READY_MSG   = 'Listening interface'
DISPATCHER_REPORT_FILE = 'peregrine-dispatcher.tsv'

BIND_KERNEL_SCRIPT     = '/home/fcp/bind-e810-kernel.sh'

class Dispatcher(Host):
	def __init__(self, hostname, peregrine_path, verbose=True):
		super().__init__('dispatcher', hostname, verbose)

		self.peregrine_path = peregrine_path
		self.dispatcher_path = f'{peregrine_path}/dispatcher'
		self.dispatcher_exe_path = f'{self.dispatcher_path}/build/Release/{DISPATCHER_EXE_NAME}'

		if not self.has_directory(self.peregrine_path):
			self.err(f'Directory not found: {self.peregrine_path}')

		if not self.has_directory(self.dispatcher_path):
			self.err(f'Directory not found: {self.dispatcher_path}')

		# Stop any instances running before running our own
		self.stop()
	
		# next, bind to kernel drivers
		self.exec(f'sudo {BIND_KERNEL_SCRIPT}', silence=True, must_succeed=False)

	def start(self, listen_iface):
		# build first
		self.exec('./build.sh', path=self.dispatcher_path, silence=True)

		# now launching dispatcher
		self.exec(f'sudo {self.dispatcher_exe_path} -i {listen_iface} > {DISPATCHER_LOG_FILE} 2>&1',
			path=self.dispatcher_path, background=True)
		
		# and wait for it to be ready
		while 1:
			time.sleep(1)

			ret, out, err = self.exec(f'cat {DISPATCHER_LOG_FILE}', capture_output=True)

			if not self.is_program_running(self.dispatcher_exe_path):
				self.log('ERROR: Dispatcher not running.')
				self.log('Dumping of log file:')
				print(out)
				exit(1)

			if DISPATCHER_READY_MSG in out:
				break

	def stop(self):
		self.kill(DISPATCHER_EXE_NAME)
		self.exec(f'rm -f {DISPATCHER_LOG_FILE}', must_succeed=False)
	
	def get_report(self):
		return self.get_files(f'{self.dispatcher_path}/{DISPATCHER_REPORT_FILE}')