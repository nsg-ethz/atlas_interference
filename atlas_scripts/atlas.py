"""
@author: Thomas Holterbach
@email : thomasholterbach@gmail.com
"""

import sys
import json


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
https://atlas.ripe.net/api/v1/measurement/?YOUR RIPE KEY HERE'


