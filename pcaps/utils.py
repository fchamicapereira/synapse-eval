#!/usr/bin/python3

from random import randint, sample

from scapy.all import *
from scapy.utils import PcapWriter

VT100_ERASE_LINE = "\33[2K\r"

def random_mac(blacklist=[]):
	mac = None
	while not mac or mac in blacklist:
		mac = f"02:00:00:{randint(0, 0xff):02x}:{randint(0, 0xff):02x}:{randint(0, 0xff):02x}"
	return mac

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

def random_ip(blacklist=[], private_only=False, internet_only=False, from_subnet=''):
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

	ip = None
	while not ip or ip in blacklist:
		ip = __random_ip(private_only=private_only, internet_only=internet_only, from_subnet=from_subnet)
	return ip

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
	flow = {
		"src_ip":   random_ip(private_only=private_only, internet_only=internet_only),
		"dst_ip":   random_ip(private_only=private_only, internet_only=internet_only),
		"src_port": random_port(),
		"dst_port": random_port(),
	}

	return flow

def create_n_unique_flows(nflows, private_only, internet_only, flows_exception=[]):
	flows_set = set()
	flows     = []

	while len(flows) < nflows:
		flow    = create_flow(private_only, internet_only)
		flow_id = get_flow_id(flow)

		if flow_id not in flows_set and flow not in flows_exception:
			flows.append(flow)
			flows_set.add(flow_id)
	
	return flows