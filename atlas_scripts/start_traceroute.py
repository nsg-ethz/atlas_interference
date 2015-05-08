import sys
import random
import time

from atlas import Measurements

import requests
import json
import random

import argparse


parser = argparse.ArgumentParser("Start traceroute on an Atlas probe towards random destinations\nWarning: You have to write in the script two RIPE KEYs (one for creating the measurements, another one for stoping the measurements, just in case ...")
parser.add_argument("n", type=int, help="Number of traceroutes to start")
parser.add_argument("id", type=int, help="ID of the Atlas probe")
parser.add_argument("dest", type=str, help="File where are stored destinations IP addresses (one IP per line)")
parser.add_argument("outfile", type=str, help="Outfile")
args = parser.parse_args()
nb_traceroutes = args.n
probe_id = args.id
outfile = args.outfile
dest = args.dest

# Copy past in this dictionnary your RIPE Key
key_traceroute = {'MY KEY':'MY KEY FOR STOPPING THE MEASUREMENT'}

# Compute start and end time
start_ts = int(time.time())

# Managing the destination set
dst_list = []
fd = open(dest, 'r')
for line in fd.readlines():
	dst_list.append(line.rstrip('\n'))
fd.close()

dst_index = 0

def get_dst ():
    global dst_index
    dst_index += 1
    return dst_list[dst_index%len(dst_list)]
# End destination set

# Open the output file
fd = open(outfile, 'a+')
fd.write("#start\t"+str(start_ts)+'\t'+str(time.time())+'\n')

# Number of traceroutes started
ntr = 0

# Then, start traceroute measurements from the Atlas probe
for key in key_traceroute:

    print key

    for i in range(0, 100):
        dst = get_dst()

        msm = Measurements()
        msm.add_traceroute(description = str(nb_traceroutes)+" traceroutes", interval=60, packets=10, target=dst, is_oneoff=True, protocol="TCP")
        msm.add_probes(value=probe_id)

        headers = {'content-type': 'application/json'}
        url = 'https://atlas.ripe.net/api/v1/measurement/'
        params = {'key': key}
        data = msm.get_json()
        print data
        r = requests.post (url, params=params, data=json.dumps(data), headers=headers)

        try:
            fd.write(str(r.json()["measurements"][0])+"\t"+key+'\t'+key_traceroute[key]+'\t'+'traceroute\t'+str(time.time())+'\n')
        except:
            print "Measurement not started "+key+" "+str(dst)
            print data
            print r
        fd.flush()

        ntr += 1
        if ntr >= nb_traceroutes:
            fd.close()
            sys.exit(0)
        
fd.close()


