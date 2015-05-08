"""
@author: Thomas Holterbach
@email : thomasholterbach@gmail.com
"""

import sys
import os
import getopt
from fabric.api import *
from fabfile import *


if __name__ == "__main__":

	try:
		opts, args = getopt.getopt(sys.argv[1:], "i:s:p:f:w:n:", ())
	except (getopt.error):
		usage()

	server_ip = None
	server_port = "6700"
	nb_flow_id = "16"
	waiting_time = "2"
	nb_ping = "10"
	clients_file = None

	for (x, y) in opts:
		if x in ('-s'):
			server_ip = y
		elif x in ('-p'):
			server_port = y
		elif x in ('-i'):
			clients_file = y
		elif x in ('-f'):
			nb_flow_id = y
		elif x in ('-w'):
			waiting_time = y
		elif x in ('-n'):
			nb_ping = y
		elif x in ('-h'):
			usage()
			sys.exit()
		else:
			usage()

	if server_ip == None and clients_file:
        print "Error: need a server IP address and a list of clients"
		sys.exit()

	execute (set_hosts, filename=pairs_file)
	execute (put_client)
	execute (start_clients, server_ip, server_port, nb_flow_id, waiting_time, nb_ping)



