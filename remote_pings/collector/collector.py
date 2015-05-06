"""
@author: Thomas Holterbach
@email : thomasholterbach@gmail.com
"""

from __future__ import print_function
import sys
import os
import shutil
import getopt
import socket
import select
import atexit
import json
import time
import struct
from sets import Set
from subprocess import PIPE, Popen

def info (*objs):
    print ("INFO: ", *objs, file=sys.stdout)

def debug (dbg_file, text):
	print (text)
	dbg_file.write ("["+time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())+"] "+text+"\n")

def error (*objs):
    print ("ERROR: ", *objs, file=sys.stderr)

def usage ():
	print ("The collector collects ping data from clients and \
store them in a database.\nWhen a client logon, the collector sends him a list of \
destinations to ping .\nClients transfert ping results in warts format. The collector\
parses them and stores RTTs and their timestamps as well as packet losses into files.\n \
\nOptions are : \n\
 -p\t--port\t\tThe port to use\n\
 -i\t--infile\tFile containing all source-destination pairs\n\
 -d\t--dir\t\tDirectory where to store the pings output\n\
 -b\t--debug\t\tDebugging file name (optional)\n")


def store_warts (warts_data, sock):
	try:
		warts2json = Popen (["sc_warts2json"], stdin=PIPE, stdout=PIPE)
		(json_data, stderr_data) = warts2json.communicate (warts_data)
	except:
		debug (dbg_file, 'ERROR : sc_warts2json')

	interval_computed = False
	# Parse json data line per line
	for line in json_data.split('\n'):
		if line == "":
			break
		try:	
			json_parsed = json.loads(line)
		except:
			debug (dbg_file, "ERROR : JSON line non-readable")
			print (line)

		fid = -1
		try:
			if json_parsed['type'] == "ping":
				store_ping (json_parsed)
				fid = json_parsed['icmp_csum']
			elif json_parsed['type'] == "trace":
				store_trace (json_parsed)
				fid = json_parsed['icmp_sum']
		except:
			debug (dbg_file, "ERROR when storing data")
			print (json_parsed)

		# Some statistics ..
		# Update time interval only for one flow id (here the flow id with a checksum = 0)
		if fid == 1 and not interval_computed:
			clients_dict[sock.getpeername ()].date_interval = time.time() - clients_dict[sock.getpeername ()].date_timestamp 
			clients_dict[sock.getpeername ()].date_timestamp = time.time()
			interval_computed = True

def store_trace (json_parsed):
	try:
		trace_file = open (output_dir+'/traceroute/'+str(json_parsed['src'])+'/'+ \
			str(json_parsed['dst'])+'/'+str(json_parsed['icmp_sum'])+'/'+'paths', 'a+')
		try:
			trace_file.write (str(json_parsed['start']['sec'])+"\t"+str(json_parsed['start']['usec'])+"\t")
			trace_file.write (str(json_parsed['hop_count'])+"\t")

			if json_parsed['stop_reason'] == 'COMPLETED':
				current_ttl = 1
				for hop in json_parsed['hops']:
					while current_ttl < hop['probe_ttl']:
						trace_file.write ("*"+"\t")
						current_ttl += 1
					trace_file.write (hop['addr']+"\t")
					current_ttl += 1
			else:
				trace_file.write ("ERROR")
			trace_file.write ("\n")
			trace_file.close ()
		except:
			debug (dbg_file, "ERROR : when reading traceroute hops")
	except:
		debug (dbg_file, "ERROR : Cannot open file")
		print (output_dir+'/traceroute/'+str(json_parsed['src'])+'/'+ \
			str(json_parsed['dst'])+'/'+str(json_parsed['dport'])+'/'+'paths', 'a+')

def store_ping (json_parsed):

	# Write the resulting rtt and timestamp in the corresponding file
	try:
		rtt_file = open (output_dir+'/'+str(json_parsed['src'])+'/'+ \
			str(json_parsed['dst'])+'/'+str(json_parsed['icmp_csum'])+'/'+'rtt', 'a+')
		try:
			for responses in json_parsed['responses']:
				rtt_file.write (str(responses['rtt'])+'\t'+ \
					str(responses['tx']['sec'])+'\t'+ \
					str(responses['tx']['usec'])+'\t'+ \
					str(responses['rx']['sec'])+'\t'+ \
					str(responses['rx']['usec'])+'\n')
			# Write some statistics about ping sent number and replies
			rtt_file.write ("stats\t"+str(json_parsed['ping_sent'])+"\t"+ \
				str(json_parsed['statistics']['replies'])+"\t"+ \
				str(json_parsed['ping_sent']- \
					json_parsed['statistics']['replies'])+"\t"+ \
					str(json_parsed['statistics']['avg'])+"\t"+ \
					str(json_parsed['statistics']['min'])+"\t"+ \
					str(json_parsed['statistics']['max'])+"\t"+ \
					str(json_parsed['statistics']['loss'])+"\n")
		except:
			if json_parsed['statistics']['replies'] == 0:
				try:
					rtt_file.write ("stats\t"+str(json_parsed['ping_sent'])+"\t"+ \
					str(json_parsed['statistics']['replies'])+"\t"+ \
					str(json_parsed['ping_sent']- \
						json_parsed['statistics']['replies'])+"\n")
				except:
					debug (dbg_file, "ERROR : Error when reading json data (2)")
			else:
				debug (dbg_file, "ERROR : Error when reading json data")
				print (json_parsed)
		rtt_file.close()
	except:
		debug (dbg_file, "ERROR : Cannot open file")
		print (output_dir+'/'+str(json_parsed['src'])+'/'+ \
			str(json_parsed['dst'])+'/'+str(json_parsed['icmp_csum'])+'/'+'rtt')

# This class defines a Client
class Client:

	socket = None
	nb_flow_id = 0
	waiting_time = "0"
	nb_ping = "0"
	dst_filename = "0"
	debug_name = "client.dbg"
	server_ip = ""
	bytes = 0
	last_bytes = 0
	dst_set = None
	date = None
	date_timestamp = None
	date_interval = None
	tv_sec = 0
	tv_usec = 0
	peername = None
	dbg_counter = 0

	# Current warts data received by this client and waiting to be completed
	# before being processed 
	current_data = ""
	

	def __init__(self, socket, pairs_file=None):	
		self.socket = socket
		self.dst_set = []		
		self.date = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
		self.date_timestamp = time.time()
		self.date_interval = 0
		self.peername = self.socket.getpeername ()

		if pairs_file != None:
			self.read_params ()

			# Read pairs (src, dst) from the pairs file
			f = open (pairs_file)
			lines = f.readlines()
			f.close()

			# Fill the pairs set
			for line in lines:
				linetab = line.split()
				if linetab[0] == self.socket.getpeername()[0]:
					self.dst_set.append (linetab[1])

	# This function deals with the incoming warts data
	# The warts data is first stored in a buffer. When the entire warts data
	# of a scamper output is received, it is then parsed and stored
	def recv_data (self):
		data = self.socket.recv (4096)
				
		# Client deliberately disconnected
		if len(data) == 0:
			debug (dbg_file, 
				"Out\t"+self.socket.getpeername ()[0]+"\t"+ \
				str(self.socket.getpeername ()[1])+"\t"+ \
				str(time.time())+"\t"+ \
				str(self.nb_flow_id)+"\t"+ \
				self.waiting_time+"\t"+ \
				self.nb_ping)

			# Remove socket and client 
			socket_list.remove (self.socket)
			del clients_dict[self.socket.getpeername ()]

			# Refresh the clients info file
			Client.write_clients (clients_info_filename, clients_dict)

		else:
			# Refresh the number of bytes received by this client
			self.bytes += len(data)
			# Refresh the last active date of the client
			self.date = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

			# Add this data in the current data
			self.current_data += data

			# Refresh the client info file
			Client.write_clients (clients_info_filename, clients_dict)

			# Get the size of the next scamper output, stored in 8 bytes
			warts_size = struct.unpack ("!q", self.current_data[:8])[0]

			# If we have received all the scamper output, we store it, keeping the
			# part of the next scamper output in the buffer
			while warts_size <= len(self.current_data) - 8:
				self.current_data = self.current_data [8:]
				store_warts (self.current_data[:warts_size], self.socket)
				self.last_bytes = len(self.current_data[:warts_size])
				self.current_data = self.current_data [warts_size:]

				if len(self.current_data) < 8:
					break
				else:
					warts_size = struct.unpack ("!q", self.current_data[:8])[0]

	# This function read the first struct sent by the client which contains the
	# client parameters
	def read_params (self):

		data = self.socket.recv (8)
		while len(data) < 8:
			data = data + self.socket.recv (8 - len(data))
		self.nb_flow_id = str(struct.unpack ("!q", data)[0])

		data = self.socket.recv (12)
		while len(data) < 12:
			data = data + self.socket.recv (12 - len(data))
		self.waiting_time = str(struct.unpack ("<12s", data)[0])
		
		data = self.socket.recv (12)
		while len(data) < 12:
			data = data + self.socket.recv (12 - len(data))
		self.nb_ping = str(struct.unpack ("<12s", data)[0])

		data = self.socket.recv (128)
		while len(data) < 128:
			data = data + self.socket.recv (128 - len(data))
		self.dst_filename = str(struct.unpack ("<128s", data)[0])

		data = self.socket.recv (128)
		while len(data) < 128:
			data = data + self.socket.recv (128 - len(data))
		self.debug_name = str(struct.unpack ("<128s", data)[0])

		data = self.socket.recv (128)
		while len(data) < 128:
			data = data + self.socket.recv (128 - len(data))
		self.server_ip = str(struct.unpack ("<128s", data)[0])

		data = self.socket.recv (8)
		while len(data) < 8:
			data = data + self.socket.recv (8 - len(data))
		self.tv_sec = str(struct.unpack ("!q", data)[0])

		data = self.socket.recv (8)
		while len(data) < 8:
			data = data + self.socket.recv (8 - len(data))
		self.tv_usec = str(struct.unpack ("!q", data)[0])

	# Send list of destinations to a client
	def send_destination (self):
		message_dst = ''
		for dst in self.dst_set:
				message_dst = message_dst+dst+'\n'
		self.socket.send (message_dst.rstrip('\n'))

	def info(self):
		return self.peername[0]+"\t"+str(self.peername[1])+"\t"+ \
			str(self.tv_sec)+"\t"+str(self.tv_usec)+"\t"+ \
			str(len(self.dst_set))+"\t"+ self.nb_flow_id+"\t"+self.waiting_time+"\t"+ \
			self.nb_ping+"\t"+str(self.bytes)+"\t"+self.date+"\t"+str(self.last_bytes)+"\t"+ \
			"%.2f" % self.date_interval+"\n"

	def __hash__(self):
		return hash(self.socket)

	@staticmethod
	def write_clients (filename, clients_dict):
			if Client.dbg_counter%20 == 0:
				clients_info = open (filename, "w", 1)
				clients_info.write ("# IP\t\tPort\ttv_sec\t\ttv_usec\t#Dst\t#FlowID\ttime\t#ping\t#bytes_received\tlast_data\t\tlast_bytes\ttime_interval\n")
				for index in clients_dict:
					clients_info.write (clients_dict[index].info())
				clients_info.close ()
				Client.dbg_counter = 0
			else:
				Client.dbg_counter += 1

	# Create the directories for a client
	def create_directories (self, output_dir):
		# Create the log directory of log files
		if not os.path.exists (output_dir+'/loglog'):
			os.makedirs (output_dir+'/loglog')

		# Create the traceroute directory
		if not os.path.exists (output_dir+'/traceroute'):
			os.makedirs (output_dir+'/traceroute')

		client_ip = self.peername [0]

		# If this client runs traceroute measurements, we create directories in the traceroute dir
		tmp_dir = output_dir
		if self.nb_ping[:2] == "NO":
			tmp_dir = output_dir+"/traceroute"

		if not os.path.exists(tmp_dir+'/'+client_ip):
			os.makedirs (tmp_dir+'/'+client_ip)

		for dst in self.dst_set:
			if not os.path.exists (tmp_dir+'/'+client_ip+'/'+dst):
				os.makedirs (tmp_dir+'/'+client_ip+'/'+dst)
		
				for flow_id in range(int(self.nb_flow_id)):
					if not os.path.exists (tmp_dir+'/'+client_ip+'/'+dst+'/'+str(flow_id+1)):
						os.makedirs (tmp_dir+'/'+client_ip+'/'+dst+'/'+str(flow_id+1))

# List of active sockets
socket_list = []
# Name of the log files and output directory
output_dir = "server_output"
debug_filename = "server.dbg"
clients_info_filename = "server.clients"

# Close sockets when exit
# Store the log files
def exit_handler ():
	for sock in socket_list:
		sock.close()

	try:
		date = str(int(time.time()))
		shutil.move (debug_filename, output_dir+"/loglog/server.dbg"+date)
		shutil.move (clients_info_filename, output_dir+"/loglog/server.clients"+date)
	except:
		print ("Connect move debug files")
atexit.register(exit_handler)

if __name__ == "__main__":

	try:
		opts, args = getopt.getopt(sys.argv[1:], "p:i:d:hb:", ("port=","infile=", \
			"dir=","help","debug="))
	except (getopt.error):
		usage()

	server_port = 6700
	pairs_file = None
	pairs_set = Set ()

	for (x, y) in opts:
		if x in ('-p', '--port'):
			server_port = int(y)
		elif x in ('-i', '--infile'):
			pairs_file = y
		elif x in ('-d', '--dir'):
			output_dir = y
			clients_info_filename = output_dir+"/"+clients_info_filename
			debug_filename = output_dir+"/"+debug_filename
		elif x in ('-b', '--debug'):
			debug_filename = y
		elif x in ('-h', '--help'):
			usage()
			sys.exit()
		else:
			usage()

	if pairs_file == None:
		usage ()
		sys.exit ()

	# Dictionnary of connected clients
	clients_dict = {}

	# Clean clients info file
	f = open (clients_info_filename, "w+")
	f.truncate ()
	f.close ()

	# Open the debugging file
	dbg_file = open (debug_filename, "w", 1)

	debug (dbg_file, "#State\tIP\t\tPort\ttime\t\tFlowID\tWait\tnbping")

	# Create the listening socket 
	sock = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
	sock.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	# Bind, listen and add socket in the socket list
	try:
		sock.bind (('', server_port))
	except socket.error as msg:
		print ('Bind failed. Error Code : '+str(msg[0])+' Message '+msg[1])
		sys.exit()

	sock.listen(50)
	socket_list.append (sock)

	# Listen for new connexion or data from clients
	while True:
		inready, outready, excepready = select.select (socket_list, [], [])

		for s in inready:
			if s == sock: 
			
				# Accept the new client
				client_sock, client_addr = s.accept()

				# Add the client to the clients set
				new_client = Client (client_sock, pairs_file)
				
				# Refresh the clients dictionnary
				if client_sock.getpeername () not in clients_dict:
					debug (dbg_file, 
						"In\t"+client_addr[0]+"\t"+str(client_addr[1])+"\t"+ \
						str(time.time())+"\t"+ \
						str(new_client.nb_flow_id)+"\t"+ \
						new_client.waiting_time+"\t"+ \
						new_client.nb_ping)

					# Add the socket to the sockets set
					socket_list.append (client_sock)
					clients_dict[client_sock.getpeername ()] = new_client
				else:
					debug (dbg_file, 
						"Bad\t"+client_addr[0]+"\t"+str(client_addr[1])+"\t"+ \
						str(time.time())+"\t"+ \
						str(new_client.nb_flow_id)+"\t"+ \
						new_client.waiting_time+"\t"+ \
						new_client.nb_ping)

				# Create the data directory for this clients
				new_client.create_directories (output_dir)

				# Send to the client a set of destinations to ping
				new_client.send_destination ()
				
				# Refresh the clients info file
				Client.write_clients (clients_info_filename, clients_dict)

			else:
				clients_dict[s.getpeername ()].recv_data ()		


