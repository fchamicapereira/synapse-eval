#!/usr/bin/env python3

from hosts.Tofino import Tofino
from hosts.Dispatcher import Dispatcher
from hosts.KitNet import KitNet
from hosts.TG_kernel import TG_kernel
from hosts.TG_DPDK import TG_DPDK

if __name__ == '__main__':
	tofino     = Tofino('tofino', '/root/peregrine')
	dispatcher = Dispatcher('gsd+e291427x1300274', '/home/fcp/peregrine')
	kitnet     = KitNet('gsd+e291427x1300274', '/home/fcp/peregrine')
	# tg_kernel  = TG_kernel('gsd+e291427x1300275')
	tg_dpdk    = TG_DPDK('gsd+e291427x1300275')