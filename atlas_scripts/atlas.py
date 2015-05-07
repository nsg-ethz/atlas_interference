"""
@author: Thomas Holterbach
@email : thomasholterbach@gmail.com
"""

################################################################################

from __future__ import print_function
import sys
import json
from sets import Set


def info (*objs):
    print ("INFO: ", *objs, file=sys.stdout)

def warning (*objs):
    print ("WARNING: ", *objs, file=sys.stderr)

def error (*objs):
    print ("ERROR: ", *objs, file=sys.stderr)

def usage (*objs):
    print ('USAGE: python '+os.path.basename(sys.argv[0])+' %s -l login -p passwd \
-s start-date -e end_date', *objs, file=sys.stderr) 
    sys.exit(0)

################################################################################

class Probe:
    
    def __init__ (self, probe_id, asn, country_code, lat, lgt, ipv4='unknown', nat="unknown", system="unknown", status="unknown", public="unknown"):
        self.probe_id = probe_id
        self.asn = asn
        self.lat = lat
        self.lgt = lgt
        self.country_code = country_code
        self.ipv4 = ipv4
        self.nat = nat
        self.system = system
        self.status = status
        self.public = public

    def __hash__(self):    
        return hash(self.probe_id)

    def __repr__(self):
        return str(self.probe_id)+'\t'+str(self.asn)+'\t'+self.country_code+'\t' \
            +str(self.lat)+'\t'+str(self.lgt)+'\t'+str(self.ipv4)+"\t"+self.nat+"\t"+self.system
    
    @staticmethod
    def header ():
        return '#ID\tASN\tCOUNTRY\tLAT\tLGT'

    def write_googlemap_marker (self, outfile=None):
        if outfile != None:
            print ('var marker = new google.maps.Marker({position: new google.maps.LatLng('+self.lat+','+self.lgt+'),map: map,title:\"'+self.probe_id+'\"});', file=outfile)

################################################################################

class Measurements:

    def __init__(self):
        self.definitions = []
        self.probes = []
        self.start_time = None
        self.stop_time = None

    def add_start_time (self, timestamp):
        self.start_time = timestamp

    def add_stop_time (self, timestamp):
        self.stop_time = timestamp

    def add_traceroute(self, description ="Mesures TH", af=4, is_oneoff="False", \
                        is_public="True", target="ripe.net", interval=900,\
                        protocol="ICMP", dontfrag="False", paris=16, packets=3, size=1):
            
        req = {}

        # Core properties
        req["type"] = "traceroute"
        req["description"] = str(description)
        req["af"] = af
        req["is_oneoff"] = str(is_oneoff)
        req["is_public"] = str(is_public)

        # Traceroute properties
        req["target"] = str(target)
        req["interval"] = interval
        req["protocol"] = str(protocol)
        req["dontfrag"] = str(dontfrag)
        req["paris"] = paris
        req["packets"] = packets
        req["size"] = size

        self.definitions.append(req)

    def add_ping(self, description ="Mesures TH", af=4, is_oneoff="False", \
                        is_public="True", target="ripe.net", interval=900,\
                        packets=3):
            
        req = {}

        # Core properties
        req["type"] = "ping"
        req["description"] = str(description)
        req["af"] = af
        req["is_oneoff"] = str(is_oneoff)
        req["is_public"] = str(is_public)

        # Traceroute properties
        req["target"] = str(target)
        req["interval"] = interval
        req["packets"] = packets

        self.definitions.append(req)

    def add_dns(self, description ="Mesures TH", af=4, is_oneoff="False", \
                        is_public="True", target="ripe.net", interval=900, \
                        udp_payload_size=512, query_argument='facebook.com', \
                        protocol="UDP"):
            
        req = {}

        # Core properties
        req["type"] = "dns"
        req["description"] = str(description)
        req["af"] = af
        req["is_oneoff"] = str(is_oneoff)
        req["is_public"] = str(is_public)

        # DNS properties
        req["target"] = str(target)
        req["interval"] = interval
        req["udp_payload_size"] = udp_payload_size
        req["query_class"] = "IN"
        req["query_type"] = "A"
        req["query_argument"] = query_argument
        req["protocol"] = protocol

        self.definitions.append(req)

    def add_ssl(self, description ="SSL TH", af=4, is_oneoff="False", \
                        is_public="True", target="ripe.net", interval=900):
            
        req = {}

        # Core properties
        req["type"] = "sslcert"
        req["description"] = str(description)
        req["af"] = af
        req["is_oneoff"] = str(is_oneoff)
        req["is_public"] = str(is_public)

        # SSL properties
        req["target"] = str(target)
        req["interval"] = interval

        self.definitions.append(req)

    def add_probes(self, requested=1, probes_type="probes", value="1"):
    
        probe = {}

        # Probe properties
        probe["requested"] = requested
        probe["type"] = str(probes_type)
        probe["value"] =  str(value)

        self.probes.append(probe)

    def get_json(self):
    
        json_data = {}
        json_data["definitions"] = self.definitions  # Definitions is a list of probe informations
        json_data["probes"] = self.probes # Probes is a list of probes definitions
        if self.start_time != None:
            json_data["start_time"] = self.start_time
        if self.stop_time != None:
            json_data["stop_time"] = self.stop_time

        return json_data

    def get_curl(self):
        return 'curl -H "Content-Type: application/json" -H "Accept: \
application/json" -X POST -d \''+json.dumps(self.get_json())+'\' \
https://atlas.ripe.net/api/v1/measurement/?key=4f93e73c-fffd-4aba-9fab-03821103260e'


################################################################################


try:
    import mechanize
except ImportError:
    error ('You must install python mechanize module')

class Atlas:

    def __init__ (self, user='noneed', passwd='noneed', debug=False):
        self.user = user
        self.passwd = passwd
        self.debug = debug

    def auth (self):
        br = mechanize.Browser()
        br.set_debug_http(self.debug)
        
        info ('Attempting to authenticate ...')                
        br.open("https://access.ripe.net")
        
        br.select_form(nr=0)
        br['username'] = self.user
        br['password'] = self.passwd
        br.submit()
    
        self.br = br
        
    def get_msm (self, msm_id, start_date=None, end_date=None, \
        outfile='msm_data.json', no_date = False):

        if start_date == None and no_date == False:
            error('You need to indicate a start date')
            sys.exit(0)

        msm_id = msm_id.rstrip('\n')

        ###################################
        ###### Date packages import #######
        ###################################
        from datetime import date, datetime
        import calendar
        import time
        import requests

        if no_date == False:        
            date_obj = date(*map(int, reversed(start_date.split("/"))))
            start_timestamp = calendar.timegm(date_obj.timetuple())        

            if end_date == None:
                end_timestamp = int(time.time())
            else: 
                date_obj = date(*map(int, reversed(end_date.split("/"))))
                end_timestamp = calendar.timegm(date_obj.timetuple())    
        
            date_line = 'start='+str(start_timestamp)+'&stop='+str(end_timestamp)
            info ('Downloading data from measurement '+str(msm_id)+'. Start \
timestamp : '+str(start_date)+'('+str(start_timestamp)+')'+'. End timestamp : '\
+str(end_date)+'('+str(end_timestamp)+')')
        
        else:
            date_line = ''
            info ('Downloading data from measurement '+str(msm_id)+'. No start and end time')
        #if self.debug:

        url = 'https://atlas.ripe.net/api/v1/measurement/'+str(msm_id)+'/result/?' \
+date_line+'&format=txt'

        #if self.debug:
        info ('URL : '+url)

        #self.br = mechanize.Browser()
        r = requests.get (url)
        return r.content
        #try:
        #    return self.br.retrieve (url, outfile) 
        #except (mechanize.HTTPError, mechanize.URLError) as e:
        #    if isinstance(e, mechanize.HTTPError):
        #        print ('HTTPError '+str(e.code))
        #    else:
        #        print ('URLError '+e.reason)
        #    return None




    def get_country_probes (self, country_code, outfile='probes_country_list.json'):

        info ('Downloading probes list of the country '+country_code)

        url = 'https://stat.ripe.net/data/atlas-probes/data.json?resource='+country_code

        info ('URL : '+url)

        probes_list = Set()
        self.br = mechanize.Browser()
        
        try:
            json_data = self.br.open(url, outfile, timeout=10.0).read()
        except (mechanize.HTTPError,mechanize.URLError) as e:
            if isinstance(e, mechanize.HTTPError):
                print ('HTTPError '+str(e.code))
            else:
                print ('URLError '+e.reason)
            return probes_list #Return an empty list if an error occurs       

        data = json.loads(json_data) 
        for probe in data["data"]["probes"]:
            nat = "unknown"
            system = "unknown"

            # Check if behind a NAT
            if "nat" in probe["tags"]:
                nat = "nat"
            elif "no-nat" in probe["tags"]:
                nat = "no-nat"

            # Check the system
            if "system-v1" in probe["tags"]:
                system = "system-v1"
            elif "system-v2" in probe["tags"]:
                system = "system-v2"
            elif "system-v3" in probe["tags"]:
                system = "system-v3"
            elif "system-v4" in probe["tags"]:
                system = "system-v4"
    

            probes_list.add(Probe(probe["id"], probe['asn_v4'], \
            probe['country_code'], probe['latitude'], probe['longitude'], \
            '0.0.0.0', nat, system, probe['status_name'], probe['is_public']))

        return probes_list


    def get_ASprobes (self, as_number, outfile='probes_list.json'):

        info ('Downloading probes list of AS'+as_number)

        url = 'https://stat.ripe.net/data/atlas-probes/data.json?resource=AS'+\
        as_number

        info ('URL : '+url)

        probes_list = Set()
        self.br = mechanize.Browser()
        
        try:
            json_data = self.br.open(url, outfile, timeout=10.0).read()
        except (mechanize.HTTPError,mechanize.URLError) as e:
            if isinstance(e, mechanize.HTTPError):
                print ('HTTPError '+str(e.code))
            else:
                print ('URLError '+e.reason)
            return probes_list #Return an empty list if an error occurs

        data = json.loads(json_data)

        for probe in data["data"]["probes"]:
            nat = "unknown"
            system = "unknown"
            if probe["status"] == 1 and probe['is_public'] == True: #Connected and public probes

                # Check if behind a NAT
                if "nat" in probe["tags"]:
                    nat = "nat"
                elif "no-nat" in probe["tags"]:
                    nat = "no-nat"

                # Check the system
                if "system-v1" in probe["tags"]:
                    system = "system-v1"
                elif "system-v2" in probe["tags"]:
                    system = "system-v2"
                elif "system-v3" in probe["tags"]:
                    system = "system-v3"
                elif "system-v4" in probe["tags"]:
                    system = "system-v4"
    
                probes_list.add(Probe(probe["id"], probe['asn_v4'], \
                probe['country_code'], probe['latitude'], probe['longitude'], \
                probe['address_v4'], nat, system))
        
        return probes_list


    def get_ASmsm (self, as_number):

        info ('Downloading measurements list of AS'+as_number)

        url = 'https://stat.ripe.net/data/atlas-targets/data.json?resource=AS'+\
        as_number

        info ('URL : '+url)
    
        msm_list = Set()
        self.br = mechanize.Browser()

        try:
            json_data = self.br.open(url).read()
        except (mechanize.HTTPError,mechanize.URLError) as e:
            if isinstance(e, mechanize.HTTPError):
                print ('HTTPError '+str(e.code))
            else:
                print ('URLError '+e.reason)
            return msm_list # Return an empty set if an error occurs

        data = json.loads(json_data)

        for msm in data["data"]["measurements"]:
            if msm["status"]["id"] == 2 and msm["type"]["id"] == 2 and msm["af"] == 4: #Ongoing  and IPv4 traceroute measurement
                msm_list.add(msm["msm_id"])
        
        return msm_list

################################################################################

if __name__ == "__main__":

    import getopt
    import sys
    import os

    try:
        opts, args = getopt.getopt(sys.argv[1:], "l:p:s:e:m:o:a:", ("login=",\
 "passwd=", "start-date=", "end-date=", "msm-id=","outfile=","aslist=",))

    except (getopt.error):
        usage()
        
    outfile = None
    end_date = None
    aslist = None

    for (x, y) in opts:
        if x in ('-s', '--start-date'):
            start_date = y
        elif x in ('-e', '--end-date'):
            end_date = y        
        elif x in ('-m', '--msm-id'):
            msm_id = int(y)
        elif x in ('-o', '--outfile'):
            outfile =  open(y, 'w', 1) # Flush every line
        elif x in ('-a', '--aslist'):
            aslist = y
        else:
            usage()

    if aslist is None:
        usage()

    #atlas = Atlas ()    
    #atlas.get_msm(msm_id, start_date, end_date=end_date, outfile=outfile)

    f = open (aslist, 'r')
    lines = f.readlines()
    f.close()

    probes_set = Set()
    atlas = Atlas ()

    for asn in lines:        
        probes_set = probes_set.union(atlas.get_ASprobes (asn.rstrip('\n')))

    for probes in probes_set:
        print (probes, file=outfile)
