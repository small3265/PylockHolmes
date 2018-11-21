import pyshark
import socket
import os.path


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
        #self.__name = self.get_comp_name()

    def get_eth_add(self):
        return self.__eth_add

    def get_mac_add(self):
        return str(self.__eth_add).replace(':', '').upper()[0:6]

    def convert_mac_add(self, eth):
        return str(eth).replace(':', '').upper()[0:6]

    def insert_packet(self, pkt):
        self.__pkt_repository.append(pkt)

    def dns_lookup(self, pkt):
        return pkt.dns.qry_name

    # access to the packet repository
    def get_packets(self):
        return self.__pkt_repository

    def display_pkt_info(self):
        for pkt in self.__pkt_repository:
            try:
                print(pkt.info)
            except AttributeError as e:
                pass

    def get_comp_name(self):
        for pkt in self.__pkt_repository:
            if pkt.highest_layer == 'BOOTP':
                try:
                    return pkt.bootp.option_hostname
                except AttributeError:
                    pass
        return 'Unknown'


    def ip_visited(self):
        visited = dict()
        for pkt in self.__pkt_repository:

            #https://thepacketgeek.com/pyshark-using-the-packet-object/
            try:
                if(pkt.ip.dst in visited.keys()):
                    visited[pkt.ip.dst] += 1
                else:

                    visited[pkt.ip.dst] = 0
            except AttributeError as e:
                pass
        return visited

    def sites_visited(self):
        visited = dict()
        for pkt in self.__pkt_repository:
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

    def mini_repr(self):
        return str(self.__eth_add) + " ||| " + load_MAC_Vendor()[self.get_mac_add()] + " ||| " + self.get_comp_name()

    def __repr__(self):
        if self.get_mac_add() in load_MAC_Vendor().keys():
            return str(self.__eth_add) + " ||| " + load_MAC_Vendor()[self.get_mac_add()] + " ||| " + self.get_comp_name() +\
                    "\n   Number of Packets = " + self.get_repo_size() + "\n      " + str(self.sites_visited()) + \
                    "\n      " + str(self.high_layers()) + "\n       " + str(self.ip_visited()) #+ \
                    #"\n      " + str(self.get_SSL_source())
        else:
            return str(self.__eth_add) + " ||| Unknown Vendor" + " ||| " + self.get_comp_name() +\
                   "\n   Number of Packets = " + \
                   self.get_repo_size() + "\n      " + str(self.sites_visited()) + \
                    "\n      " + str(self.high_layers()) + "\n       " + str(self.ip_visited()) #+ \
                    #"\n      " + str(self.get_SSL_source())

    def display_packets(self):
        for pkt in self.__pkt_repository:
            print(pkt)

    def display_highest_layer(self):
        for pkt in self.__pkt_repository:
            print(pkt.highest_layer)

    def display_SSL(self):
        for pkt in self.__pkt_repository:
            try:
                if(pkt.highest_layer == 'SSL'):
                    print(pkt)
            except AttributeError:
                pass

    def get_SSL_source(self):
        sources = dict()
        for pkt in self.__pkt_repository:
            if(pkt.highest_layer == 'SSL'):
                if self.convert_mac_add(pkt.eth.src) in load_MAC_Vendor().keys():
                    if (pkt.eth.src in sources.keys()):
                        sources[load_MAC_Vendor()[self.convert_mac_add(pkt.eth.src)]] += 1
                    else:
                        sources[self.convert_mac_add(pkt.eth.src)] = 0
        return sources

    def display_browser(self):
        for pkt in self.__pkt_repository:
            try:
                if(pkt.highest_layer == 'BROWSER'):
                    print(pkt)
            except AttributeError:
                pass


class Hunter():

    def __init__(self, capFile=None):
        if(capFile == None):
            self.__capFile = pyshark.FileCapture('mult2.pcap')
        else:
            self.__capFile = pyshark.FileCapture(capFile)
        self.__targetList = list()
        self.__cf = capFile

    def load_cap_file(self, capFile):

        try:
            if os.path.isfile(capFile):
                self.__capFile = pyshark.FileCapture(capFile)
                self.__cf = capFile
            else:
                print("File does not exist")
                return
        except IOError as e:
            print("Issue opening file")
            return
        finally:
            print("Capture file loaded")
            return


    def acquire_targets(self):
        #if self.__capFile:
        for pkt in self.__capFile:
            if (not self.target_exists(pkt.eth.src)):
                self.__targetList.append(Target(pkt.eth.src))
                #print(len(self.__targetList))
            elif(self.target_exists(pkt.eth.src)):
                self.get_target(pkt.eth.src).insert_packet(pkt)
        #else:
        #    print("No capture file selected")



    def target_exists(self, eth):
        for tt in self.__targetList:
            if(tt.get_eth_add() == eth):
                return True
        return False

    def get_target(self, eth):
        for tt in self.__targetList:
            if tt.get_eth_add() == eth:
                return tt

    def print_target_data(self, num=None):
        if num == None:
            for tt in self.__targetList:
                tt.display_packets()
        elif num >= 0 and num < len(self.__targetList):
            self.__targetList[num].display_packets()
        else:
            print("Number out of range of target list")

    def print_highest_layers(self, num=None):
        if num == None:
            for tt in self.__targetList:
                tt.display_highest_layer()
        elif num >= 0 and num < len(self.__targetList):
            self.__targetList[num].display_highest_layer()
        else:
            print("Number out of range of target list")

    def get_target_list(self):
        return self.__targetList

    def get_mini_target_list(self):
        tempList = list()
        for tg in self.__targetList:
            tempList.append(tg.mini_repr())
        return tempList

    def get_target_total(self):
        return len(self.__targetList)

    def get_target_num(self, num):
        if num >= 0 and num < len(self.__targetList):
            return self.__targetList[num]

    def print_target_list(self):
        for tt in self.__targetList:
            print(tt)

    def print_file_path(self):
        print(self.__cf)

    def print_2(self):
        print(self.__capFile[2])




