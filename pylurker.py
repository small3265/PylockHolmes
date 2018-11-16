import pyshark
import socket



# function to create a MAC address to vendor dictionary
def load_MAC_Vendor():
    macVendorList = dict()
    #https://gist.github.com/aallan/b4bb86db86079509e6159810ae9bd3e4
    handle = open("mac-vendor.txt", 'r', encoding='utf-8')
    c = handle.readlines()
    for line in c:
        macVendorList[line[0:6]] = line[7:].replace('\t', '').replace('\n','')
    return macVendorList

#https://docs.python.org/2/library/socket.html#socket.gethostbyaddr
# using sockets to acquire URL
def url_lookup(ip_add):
    #https: // bytes.com / topic / python / answers / 20127 - how - do - i - get - info - exception
    try:
        hostname, aliases, hostip = socket.gethostbyaddr(ip_add)
    except socket.herror:
        return "Unknown"
    return hostname


class Target:
    total_targets = 0
    def __init__(self, eth = None):
        self.__id = Target.total_targets
        Target.total_targets += 1
        self.__eth_add = eth
        self.__pkt_repository = list()

    def get_eth_add(self):
        return self.__eth_add

    def get_mac_add(self):
        return str(self.__eth_add).replace(':', '').upper()[0:6]

    def insert_packet(self, pkt):
        self.__pkt_repository.append(pkt)

    def dns_lookup(self, pkt):
        return pkt.dns.qry_name

    # access to the packet repository
    def get_packets(self):
        return self.__pkt_repository

    def sites_visited(self):
        visited = dict()
        for pkt in self.__pkt_repository:
            """
            #https://thepacketgeek.com/pyshark-using-the-packet-object/
            try:
                if(pkt.ip.dst in visited.keys()):
                    visited[pkt.ip.dst] += 1
                else:
                    visited[pkt.ip.dst] = 0
            except AttributeError as e:
                pass
            """
            try:
                if (pkt.dns.qry_name in visited.keys()):
                    visited[pkt.dns.qry_name] += 1
                else:
                    visited[pkt.dns.qry_name] = 0
            except AttributeError as e:
                pass
        #https: // www.datacamp.com / community / tutorials / python - dictionary - comprehension
        #return {url_lookup(key):value for (key,value) in visited.items()}
        return visited

    def get_repo_size(self):
        if(not self.__pkt_repository):
            return "0"
        else:
            return str(len(self.__pkt_repository))


    def high_layers(self):
        layers = dict()
        for pkt in self.__pkt_repository:
            if(pkt.highest_layer in layers.keys()):
                layers[pkt.highest_layer] += 1
            else:
                layers[pkt.highest_layer] = 0
        return layers

    def __repr__(self):
        if self.get_mac_add() in load_MAC_Vendor().keys():
            return str(self.__eth_add) + " ||| " + load_MAC_Vendor()[self.get_mac_add()] + \
                    "\n   Number of Packets = " + self.get_repo_size() + "\n      " + str(self.sites_visited()) + \
                    "\n      " + str(self.high_layers())
        else:
            return str(self.__eth_add) + " ||| Unknown Vendor" + "\n   Number of Packets = " + \
                   self.get_repo_size() + "\n      " + str(self.sites_visited()) + \
                    "\n      " + str(self.high_layers())


class Hunter():

    def __init__(self, capFile=None):
        if(capFile == None):
            self.__capFile = pyshark.FileCapture('mult2.pcap')
        else:
            self.__capFile = pyshark.FileCapture(capFile)
        self.__targetList = list()
        self.__cf = capFile


    def acquire_targets(self):
        for pkt in self.__capFile:
            if (not self.target_exists(pkt.eth.src)):
                self.__targetList.append(Target(pkt.eth.src))
                print(len(self.__targetList))
            elif(self.target_exists(pkt.eth.src)):
                self.get_target(pkt.eth.src).insert_packet(pkt)



    def target_exists(self, eth):
        for tt in self.__targetList:
            if(tt.get_eth_add() == eth):
                return True
        return False

    def get_target(self, eth):
        for tt in self.__targetList:
            if tt.get_eth_add() == eth:
                return tt


    def get_target_list(self):
        return self.__targetList

    def print_target_list(self):
        for tt in self.__targetList:
            print(tt)

    def print_file_path(self):
        print(self.__cf)

    def print_2(self):
        print(self.__capFile[2])




