import sys
import random
import time

from atlas import Measurements

import requests
import json
import random

import argparse


parser = argparse.ArgumentParser("Start ping on an Atlas probe toward a destination\nWarning: You have to write in the script two RIPE KEYs (one for creating the measurements, another one for stoping the measurements, just in case ...")
parser.add_argument("id", type=int, help="ID of the Atlas probe")
parser.add_argument("d", type=str, help="Destination IP address")
parser.add_argument("o", type=str, help="Outfile where measurement IDs will be stored")
args = parser.parse_args()
probe_id = args.id
destination = args.d
outfile = args.o

# Copy past in this dictionnary your RIPE Key
key_ping = {'MY KEY':'MY KEY FOR STOPPING THE MEASUREMENT'}

# Measurement start time offset
offset_ping = 30

# Compute start and end time
start_ts = int(time.time()+offset_ping)
end_ts = int(time.time()+offset_ping+20000)

# Open the output file
fd = open(outfile, 'a+')
fd.write("#start\t"+str(start_ts)+'\t'+str(time.time())+"\n")

# Start ping measurements toward the collocated Atlas probes
for key in key_ping:

    print key
    for i in range(0, 10):
        msm = Measurements()
        msm.add_ping(description = "ping TH", interval=60, packets=2, target=destination, is_oneoff=False)
        msm.add_probes(value=probe_id)
        msm.add_start_time(start_ts+6*i)
        msm.add_stop_time(end_ts)

        headers = {'content-type': 'application/json'}
        url = 'https://atlas.ripe.net/api/v1/measurement/'
        params = {'key': key}
        data = msm.get_json()

        r = requests.post (url, params=params, data=json.dumps(data), headers=headers)

        try:
            fd.write(str(r.json()["measurements"][0])+"\t"+key+'\t'+key_ping[key]+'\t'+'ping'+'\n')
        except:
	        print "Measurement not started "+key

    fd.flush()
fd.close()


