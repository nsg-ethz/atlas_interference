#!/bin/sh

####
# @author Thomas Holterbach
# @email thomasholterbach@gmail.com
# @date 31 oct 2014
####

####
# This scripts aim to ping flood a destination. Pings are sent from NL Ring nodes
# In order to increase the ping frequency, each hour, a new Ring will start to
# perform ping toward the destination
####

server="147.28.0.37"
ring_nodes_file="ring_list"

for ring_node in $(cat $ring_nodes_file)
do
	
	fab set_host:$ring_node start_one_client:$server,6700,32,1,20 -i /home/thomas/.ssh/nlring/id_rsa
	sleep 3600
done


