import pyshark


class Target:
    total_targets = 0
    def __init__(self, id = None, eth = None):
        self.__id = total_targets
        Target.total_targets += 1
        self.__eth_Add = eth
        self.__pkt_repository = list()

    def get_eth_add(self):
        return self.__eth_Add

class Hunter():

    def __init__(self, capFile=None):
        self.capFile = pyshark.FileCapture(capFile)
        self.targetList = list()



    def search_targets(self):
        for pkt in self.capFile:
            if (not self.target_exists(pkt.eth.src)):
                self.targetList.append(Target(pkt.id.src, pkt.eth.src))


    def target_exists(self, eth):
        for tt in self.targetList:
            if(tt.get_eth_add() == eth):
                return True
        return False


    def get_target_list(self):
        return self.targetList

    def print_targe_list(self):
        for tt in self.targetList:
            print(tt)

macVendorList = dict()
macAddressList = list()
def load_MAC_Vendor():
    macVendorList = dict()
    handle = open("mac-vendor.txt", 'r', encoding='utf-8')
    c = handle.readlines()
    for line in c:
        macVendorList[line[0:6]] = line[7:].replace('\t', '').replace('\n','')
    return macVendorList
