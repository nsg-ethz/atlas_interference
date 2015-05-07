import requests
import argparse


parser = argparse.ArgumentParser("Stop a set of measurement")
parser.add_argument("file", type=str, help="File where to find the measurement IDs as well as the RIPE KEY")
args = parser.parse_args()
filename = args.file

fd = open(filename, 'r')
for line in fd.readlines():
    linetab = line.split('\t')
    if linetab[0][0] != "#":
        key = linetab[2].rstrip('\n')
        msm_id = int(linetab[0])

        print key
        print msm_id

        url = 'https://atlas.ripe.net/api/v1/measurement/'+str(msm_id)+'/'
        params = {'key': key}
        headers = {'--dump-header': '-'}

        r = requests.delete(url, params=params)
        print r.text
