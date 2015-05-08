from fabric.api import *

env.user = "WRITE YOUR USERNAME HERE"
env.key_filename = "WRITE THE LOCATION YOUR SSH IDENTITY FILE (usually a private key)"

####
# Read the input file and create the set of hosts. One host per line.
####
def set_hosts(filename = ''):
	try:
		env.hosts = open(filename, 'r').readlines()
	except:
		print "Cannot set hosts"

####
# Put client.c and Makefile in the client, and create the binary using make
####
def put_client ():
	try:
		put ("../client/client.c")
		put ("../client/Makefile")
		run ("make")
	except:
		print "Cannot create the client"

####
# Start all the client.
####
def start_clients (server_ip, server_port, nb_flow_id, waiting_time, nb_ping):
	try:
		run ("touch tmp.sh && chmod 700 tmp.sh && printf \"#!/bin/bash\nnohup ./client -s "+server_ip+" -p "+server_port+" -f "+nb_flow_id+" -w "+waiting_time+" -n "+nb_ping+" >& /dev/null < /dev/null &\n\" > tmp.sh")
		run ("nohup ./tmp.sh &> nohup.out")
	except:
		print "Cannot start the client"


