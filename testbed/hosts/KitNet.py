#!/usr/bin/env python3

from .Host import Host

import time
import os

KITNET_EXE_NAME  = 'python' # oof

KITNET_LOG_FILE  = '/tmp/kitnet.log'
KITNET_READY_MSG = 'Listening on'

class KitNet(Host):
	def __init__(self, hostname, peregrine_path, verbose=True):
		super().__init__('kitnet', hostname, verbose)

		self.peregrine_path  = peregrine_path
		self.kitnet_path     = f'{peregrine_path}/plugins/kitnet'
		self.kitnet_exe_path = f'{self.kitnet_path}/kitnet.py'

		if not self.has_directory(self.peregrine_path):
			self.err(f'Directory not found: {self.peregrine_path}')

		if not self.has_directory(self.kitnet_path):
			self.err(f'Directory not found: {self.kitnet_path}')

		# Stop any instances running before running our own
		self.stop()
	
	def start(self, feature_map_file, ensemble_layer_file, output_layer_file, train_stats_file):
		kitnet = self.kitnet_exe_path
		args = [
			'--feature_map', feature_map_file,
			'--ensemble_layer', ensemble_layer_file,
			'--output_layer', output_layer_file,
			'--train_stats', train_stats_file,
		]

		cmd = f'{kitnet} {" ".join(args)} > {KITNET_LOG_FILE} 2>&1'
		
		# now launching kitnet model plugin
		self.exec(cmd, path=self.kitnet_path, background=True)

		# and wait for it to be ready
		while 1:
			time.sleep(1)

			ret, out, err = self.exec(f'cat {KITNET_LOG_FILE}', capture_output=True)

			if not self.is_program_running(self.kitnet_exe_path):
				self.log('ERROR: KitNet not running.')
				self.log('Dumping of log file:')
				print(out)
				exit(1)

			if KITNET_READY_MSG in out:
				break

	def stop(self):
		self.kill(KITNET_EXE_NAME)