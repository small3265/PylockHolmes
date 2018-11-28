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
    """ Individual Target Class that is identified by a unique Ethernet ID"""
    total_targets = 0
    def __init__(self, eth = None):
        self.__id = Target.total_targets
        Target.total_targets += 1
        self.__eth_add = eth
        self.__pkt_repository = list()
        #self.__name = self.get_comp_name()

    #getter function for ethernet address
    def get_eth_add(self):
        return self.__eth_add

    # getter function to seperate and get the first 6 hexidecimal ethernet to get mac vendor lookup
    def get_mac_add(self):
        return str(self.__eth_add).replace(':', '').upper()[0:6]

    # converts a given ethernet address to mac address
    def convert_mac_add(self, eth):
        return str(eth).replace(':', '').upper()[0:6]

    # allows insertion of packet into private list
    def insert_packet(self, pkt):
        self.__pkt_repository.append(pkt)

    # returns dns qry name
    def dns_lookup(self, pkt):
        return pkt.dns.qry_name

    # access to the packet repository
    def get_packets(self):
        return self.__pkt_repository

    # gives packet in for all packets in target
    def display_pkt_info(self):
        for pkt in self.__pkt_repository:
            try:
                print(pkt.info)
            except AttributeError as e:
                pass

    # get packets with a matching highest layer
    def print_lay_select(self, layer):
        for pkt in self.__pkt_repository:
            if(pkt.highest_layer == layer):
                print(pkt)

    # Get the computer name from the BOOTP Layer
    def get_comp_name(self):
        for pkt in self.__pkt_repository:
            if pkt.highest_layer == 'BOOTP':
                try:
                    return pkt.bootp.option_hostname
                except AttributeError:
                    pass
        return 'Unknown'

    # returns all IP visited by the target using pkt.ip.dst
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

    # attempt to lookup the sites visited by a target
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

    # return number of packets in repository
    def get_repo_size(self):
        if(not self.__pkt_repository):
            return "0"
        else:
            return str(len(self.__pkt_repository))

    # return dict of all highest layers and number of time layer exists
    def high_layers(self):
        layers = dict()
        for pkt in self.__pkt_repository:
            if(pkt.highest_layer in layers.keys()):
                layers[pkt.highest_layer] += 1
            else:
                layers[pkt.highest_layer] = 0
        return layers

    # get highest layers shown throughout all packets
    def get_high_layers(self):
        hlayers = list()
        for pkt in self.__pkt_repository:
            if(not pkt.highest_layer in hlayers):
                hlayers.append(pkt.highest_layer)
        return hlayers

    # this returns the vendor by checking the vendor ID list
    def get_vendor(self):
        if self.get_mac_add() in load_MAC_Vendor().keys():
            return load_MAC_Vendor()[self.get_mac_add()]
        else:
            return "Unknown Vendor"

    # quick representation for printing out
    def mini_repr(self):
        return str(self.__eth_add) + " ||| " + self.get_vendor() + " ||| " + self.get_comp_name()

    # Overriding the __repr__ fuction
    def __repr__(self):
        if self.get_mac_add() in load_MAC_Vendor().keys():
            return str(self.__eth_add) + " ||| " + self.get_vendor() + " ||| " + self.get_comp_name() +\
                    "\n   Number of Packets = " + self.get_repo_size() + "\n      " + str(self.sites_visited()) + \
                    "\n      " + str(self.high_layers()) + "\n       " + str(self.ip_visited()) #+ \
                    #"\n      " + str(self.get_SSL_source())
        else:
            return str(self.__eth_add) + " ||| Unknown Vendor" + " ||| " + self.get_comp_name() +\
                   "\n   Number of Packets = " + \
                   self.get_repo_size() + "\n      " + str(self.sites_visited()) + \
                    "\n      " + str(self.high_layers()) + "\n       " + str(self.ip_visited()) #+ \
                    #"\n      " + str(self.get_SSL_source())

    # print all packets in list
    def display_packets(self):
        for pkt in self.__pkt_repository:
            print(pkt)

    # print all highest layers in packet list
    def display_highest_layer(self):
        for pkt in self.__pkt_repository:
            print(pkt.highest_layer)

    # print all SSL layers
    def display_SSL(self):
        for pkt in self.__pkt_repository:
            try:
                if(pkt.highest_layer == 'SSL'):
                    print(pkt)
            except AttributeError:
                pass

    # attempt to get all the SSL sources for requests
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

    # return all browser layers
    def display_browser(self):
        for pkt in self.__pkt_repository:
            try:
                if(pkt.highest_layer == 'BROWSER'):
                    print(pkt)
            except AttributeError:
                pass

    # get a specific packet by number
    def get_packet_by_num(self, num):
        if num >= 0 and num < len(self.__pkt_repository):
            return self.__pkt_repository[num]
        else:
            print("Packet is out of range")

    # displays a quick summary of all packets in repository
    def display_packet_summary(self):
        build_string = ""
        for i, pkt in enumerate(self.__pkt_repository):
            lay = pkt.layers
            #[str(f).lstrip('<').rstrip(' Layer>') for f in lay]
            build_string += str(i) + " - "
            for l in lay:

                build_string += str(l._layer_name).upper()
                if not l == lay[-1]:
                    build_string += "-->"
                else:
                    build_string += "\n"
        return build_string

    # get length of packet repository
    def get_repo_len(self):
        return len(self.__pkt_repository)

class Hunter():
    """ Hunter class parses capture file directly and delegates targets"""
    def __init__(self, capFile=None):
        """if(capFile == None):
            self.__capFile = pyshark.FileCapture('mult2.pcap')
        else:
            self.__capFile = pyshark.FileCapture(capFile)
        """
        self.__capFile = capFile
        self.__targetList = list()
        self.__cf = capFile

    # loading a live capture into the hunter object
    def load_cap_live(self, capFile):
        self.__capFile = capFile
        self.__cf = "Live_Capture"
        print("Live Capture File Loaded")

    # Loading of a file capture into the hunter object
    def load_cap_file(self, capFile):
        try:
            if os.path.isfile(capFile):
                self.__capFile = pyshark.FileCapture(capFile,)
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

    # Main function that uses the ethernet.source to delegate most targets on the network
    def acquire_targets(self, mode=None):
        #if mode is live capture there is an inherent error in the capture file
        # the file indicates a specific number of packets however, there are much more in the file itself
        if mode == "Live":
            i=0
            for pkt in self.__capFile:
                # limit packet analysis to only 200
                if (i == 200):
                    return
                if (not self.target_exists(pkt.eth.src)):
                    i += 1
                    print("Packets analyzed: ",i)
                    self.__targetList.append(Target(pkt.eth.src))
                    #print(len(self.__targetList))
                elif(self.target_exists(pkt.eth.src)):
                    i += 1
                    print("Packets analyzed: ", i)
                    self.get_target(pkt.eth.src).insert_packet(pkt)
        else:
            #for regular file capture we just create targets and append them to that target list they belong to.
            for pkt in self.__capFile:
                if (not self.target_exists(pkt.eth.src)):
                    self.__targetList.append(Target(pkt.eth.src))
                    self.get_target(pkt.eth.src).insert_packet(pkt)
                elif(self.target_exists(pkt.eth.src)):
                    self.get_target(pkt.eth.src).insert_packet(pkt)

    # check to see if target exist by ethernet address
    def target_exists(self, eth):
        for tt in self.__targetList:
            if(tt.get_eth_add() == eth):
                return True
        return False

    # return target by ethernet address
    def get_target(self, eth):
        for tt in self.__targetList:
            if tt.get_eth_add() == eth:
                return tt

    # call to print all packets associated with target
    def print_target_data(self, num=None):
        if num == None:
            for tt in self.__targetList:
                tt.display_packets()
        elif num >= 0 and num < len(self.__targetList):
            self.__targetList[num].display_packets()
        else:
            print("Number out of range of target list")

    # call to print the highest layers associated with target
    def print_highest_layers(self, num=None):
        if num == None:
            for tt in self.__targetList:
                tt.display_highest_layer()
        elif num >= 0 and num < len(self.__targetList):
            self.__targetList[num].display_highest_layer()
        else:
            print("Number out of range of target list")

    # getter function for target list
    def get_target_list(self):
        return self.__targetList

    # getter function for different representation of target list
    def get_mini_target_list(self):
        tempList = list()
        for tg in self.__targetList:
            tempList.append(tg.mini_repr())
        return tempList

    # get length of target list
    def get_target_total(self):
        return len(self.__targetList)

    # get a target by a number in the target list
    def get_target_num(self, num):
        if num >= 0 and num < len(self.__targetList):
            return self.__targetList[num]

    # simple print of target list
    def print_target_list(self):
        for tt in self.__targetList:
            print(tt)

    # printing the current file name in the directory
    def print_file_path(self):
        print(self.__cf)

    # test print of second cap
    def print_2(self):
        print(self.__capFile[2])

    # print the full cap file
    def print_full_cap(self):
        for pkt in self.__capFile:
            print(pkt)

    # getter function for the hunter's capfile
    def get_cap(self):
        return self.__capFile

    # flushing all the information in the hunter object and close any asynced loops
    def flush(self):
        if self.__capFile:
            self.__capFile._close_async()
        self.__capFile = None

        self.__cf = None
        self.__targetList.clear()

    def print_percentage(self):
        per_dict = dict()
        tc = 0
        for pkt in self.__capFile:
            if (pkt.highest_layer in per_dict.keys()):
                per_dict[pkt.highest_layer] += 1
                tc += 1
            else:
                per_dict[pkt.highest_layer] = 1
                tc += 1

        d = {k: round((v / sum(per_dict.values())) * 100, 2) for (k, v) in per_dict.items()}

        tupList = [(v, k) for k, v in d.items()]

        sort_list = [b for a, b in sorted((tup[0], tup) for tup in tupList)]
        print("{0:22} {1}".format("Highest Layer", "%"))
        print("_" * 26)
        for item in sort_list:
            print("{0:20} {1:>5}".format(item[1], item[0]))
        print("_" * 26)
        print("Total               100.00")

