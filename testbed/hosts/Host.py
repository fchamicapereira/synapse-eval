#!/usr/bin/env python3

import subprocess

class Host:
	def __init__(self, name, hostname, verbose=True):
		self.name = name
		self.hostname = hostname
		self.verbose = verbose
		self.test_connection()

	def exec(self, cmd, path=None, silence=False, background=False,
			must_succeed=True, capture_output=False):
		assert(type(cmd) == str)

		if self.verbose:
			self.log(f'exec \"{cmd}\"')

		remote_cmd = [
			'source ~/.bashrc',
			'source ~/.profile',
		]

		if path:
			remote_cmd.append(f'cd {path}')
		
		remote_cmd.append(cmd)
		remote_cmd = " && ".join(remote_cmd)

		ssh_flags = [ '-o', 'PasswordAuthentication=no' ]

		if background:
			ssh_flags.append('-f')
		
		cmd = [ 'ssh' ] + ssh_flags + [ self.hostname, remote_cmd ]

		if silence or capture_output:
			stdout = subprocess.PIPE
			stderr = subprocess.PIPE
		else:
			stdout = subprocess.DEVNULL if background else None
			stderr = subprocess.DEVNULL if background else None

		proc = subprocess.run(cmd, stdout=stdout, stderr=stderr)

		if not background and must_succeed and proc.returncode != 0:
			self.log(f'Command failed.')
			self.log(f'  command:  \"{" ".join(cmd)}\"')
			self.log(f'  ret code: {proc.returncode}')

			if silence or capture_output:
				self.log('  stdout:')
				print(proc.stdout)

				self.log('  stderr:')
				print(proc.stderr)

			exit(1)

		out = proc.stdout.decode('utf-8') if capture_output else None
		err = proc.stderr.decode('utf-8') if capture_output else None

		return proc.returncode, out, err
	
	def test_connection(self):
		ret, _, _ = self.exec('hostname', silence=True, must_succeed=False)

		if ret != 0:
			self.log(f'ERROR: connection with host {self.hostname} failed. Exiting.')
			exit(1)
	
	def send_files(self, src, dst):
		cmd = [ 'rsync', '-avz', '--progress', src, f'{self.hostname}:{dst}' ]
		proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

		if proc.returncode != 0:
			self.log(f'Command failed (ret={proc.returncode}).')
			exit(1)
	
	def get_files(self, src, dst="."):
		cmd = [ 'rsync', '-avz', '--progress', f'{self.hostname}:{src}', dst ]
		proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		target = f'{dst}/{src.split("/")[-1]}'
		
		if proc.returncode != 0:
			self.log(f'Command failed (ret={proc.returncode}).')
			exit(1)
		
		return target
	
	def has_directory(self, directory):
		cmd = f'test -d {directory}'
		code, _, _ = self.exec(cmd, silence=True, must_succeed=False)
		return code == 0
	
	def has_file(self, directory):
		cmd = f'test -f {directory}'
		code, _, _ = self.exec(cmd, silence=True, must_succeed=False)
		return code == 0
	
	def kill(self, program_name):
		cmd = f'sudo killall {program_name} || true'
		self.exec(cmd, silence=True, must_succeed=False)
	
	def is_program_running(self, path_to_executable):
		testing_prog = f'ps -A  -o pid,args | grep {path_to_executable}'
		_, stdout, _ = self.exec(testing_prog, silence=True, capture_output=True, must_succeed=False)
		num_matches = len(list(filter(None, stdout.split('\n'))))

		# at least 3 because:
		#  1 for the ps program
		#  1 for the grep program
		#  1 for the actual program
		#  (maybe one additionally for the sudo program, or a mother script)
		return num_matches >= 3
	
	def log(self, msg):
		print(f'[{self.name}] {msg}')
	
	def err(self, msg):
		print(f'[{self.name}] ERROR: {msg}')
		exit(1)