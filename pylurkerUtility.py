import os
import os.path
import sys
import invade
import pylurker
import warnings

if not sys.warnoptions:
    warnings.simplefilter("ignore")

def wifi_scan():
    print("hi")
command_dict = {'wifi' : invade.getNetworkList}
connect_dict = {''}
intro_string = """
                  ____________________________________________________________________________________
                  |                                                                                  |
                  |        _________         ___                           __                        |
                  |       /  ____  /        /  /                          / /                        |
                  |      /  /___/ /        /  /                          / /  __                     |
                  |     /  ______/        /  /                          / /  / /  ________           |
                  |    /  /  __    __    /  /    __    __   __  __     / /_ / /  / ____  /  __  __   |
                  |   /  /   \ \  / /   /  /    / /   / /  / /_/_ \   /   ___/  / /___/_/  / /_/_ \  |
                  |  /  /     \ \/ /   /  /__  / /___/ /  / ___/ \/  / /\ \    / /_____   / ___/ \|  |
                  | /__/       \  /   /_____/ /_______/  /_/        /_/  \_\  /_______/  /_/         |
                  |            / /                                                                   |
                  |           /_/                                                                    |
                  |__________________________________________________________________________________|
                  Type [List] to see available commands\n"""

#https://stackoverflow.com/questions/8220108/how-do-i-check-the-operating-system-in-python
#https://stackoverflow.com/questions/4810537/how-to-clear-the-screen-in-python
def clearScreen():
    if sys.platform == "linux" or sys.platform == "linux2" or sys.platform == "darwin":
        os.system("clear")
    elif sys.platform == "win32" or sys.platform == "win64":
        os.system("cls")
    else:
        print("Error: Unknown operating system")

class CommandLine():
    def __init__(self):
        self.__hunter = pylurker.Hunter()
        self.__current_target = None
        self.__current_network = None
        self.__network_list = list()
        self.__pcap_files = list()
        self.__current_file = None
        self.__input_string = ""
        self.__prompt_string = "PyLurker >>> "
        self.__options = ["[List]       | List of all available commands",
                        "[Scan]       | Return a list of all available networks",
                        "[Connect]    | Attempt connect to a network",
                        "[Load]       | Load a .pcap file",
                        "[Files]      | List of .pcap files in current folder",
                        "[Hunt]       | Once .pcap loaded, acquire a list of targets",
                        "[Show]       | Show target list",
                        "[Stats]      | Show general stats on target list",
                        "[Inspect]    | Inspect a specific target",
                        "[Current]    | Show current target",
                        "[GetPack]    | Get specific packet from target",
                        "[GetLayer]   | Get packets with specific layer"
                        "[CapPack]    | Show all packets in capture file",
                        "[TarPack]    | Show all packets of a target",
                        "[CapSave]    | Save the current .pcap file",
                        "[TarSave]    | Save target's packets to file",
                        "[Sniff]      | Live capture on current network]"]
        self.__command_dict = {'list': self.display_commands, 'scan': self.get_networks,
                            'connect' : self.connect_networks, 'load': self.load_file,
                            'files': self.get_files, 'hunt': self.hunt_targets,
                            'show': self.show_targets, 'stats': self.show_stats,
                            'cappack': self.print_full, 'tarpack': self.print_tarpack,
                            'inspect': self.inspect_target, 'getpack': self.get_pkt_target,
                            'current': self.show_current}



        self.begin()

    def display_commands(self):
        print("\nCommand List:")
        for item in self.__options:
            print(item)
        print("")

    def get_networks(self):
        self.__network_list = invade.getNetworkList()
        for i, net in enumerate(self.__network_list):
            print(i+1, " - ", net)

    def connect_networks(self):
        print("Still not available")

    def get_files(self):
        fileList = list()
        fileList.extend([f for f in os.listdir(os.curdir) if f.endswith('.pcap')])
        print("\nPCAP Files in current directory:")
        for f in fileList:
            #https: // stackoverflow.com / questions / 2104080 / how - to - check - file - size - in -python
            print(f, "   File Size: ", round(os.path.getsize(f) / 1048576, 1), "MB")
        print("")
        self.__pcap_files = fileList

    def load_file(self):
        check = True
        print("\nPlease select file from list below:")
        self.get_files()
        fileName = ""
        while(check):
            fileName = input("Select File >>>")
            if fileName.lower() == "back":
                return
            if(not fileName.endswith('.pcap')):
                fileName = fileName + '.pcap'

            if not fileName in self.__pcap_files:
                print("File Not in List, please select file or type 'back'")
            else:
                self.__current_file = fileName
                check = False
        print(self.__current_file + " is loaded and ready to go! Happy Hunting!")
        return


    def connect_menu(self):
        print("hi")

    def hunt_targets(self):
        print("\nBeginning Hunt")
        self.__hunter.load_cap_file(self.__current_file)
        self.__hunter.acquire_targets()
        print("\n   ", self.__hunter.get_target_total()," targets acquired!")
        return


    def show_targets(self):
        tempList = self.__hunter.get_mini_target_list()
        for i, tg in enumerate(tempList):
            print(i+1, "-", tg)
        print("")
    def show_stats(self):
        tempList = self.__hunter.get_target_list()
        for i, tg in enumerate(tempList):
            print(i+1, "-", tg)

    def begin(self):
        exit_flag = False
        print(intro_string)
        while(not exit_flag):

            self.__input_string = input(self.__prompt_string)
            if(self.__input_string.lower() == "exit"):
                exit_flag = True
            if self.__input_string.lower() in self.__command_dict.keys():
                self.__command_dict[self.__input_string]()

    def print_full(self):
        self.__hunter.print_full_cap()

    def show_current(self):
        print(self.__current_target)

    def inspect_target(self):
        print("\nPlease select target from list below using associated number:")
        self.show_targets()
        check = True
        while(check):
            tg_num = input("Target select >>>")
            if tg_num.lower() == "back":
                return
            if tg_num.isnumeric() and int(tg_num) >= 1 and int(tg_num) <= self.__hunter.get_target_total():
                self.__current_target = self.__hunter.get_target_num(int(tg_num)-1)
                print("Current target = ", self.__current_target.mini_repr())
                check = False
            else:
                print("Please select a number between 1 and ", self.__hunter.get_target_total(), ". Or type 'back'")
        return

    def print_tarpack(self):
        if not self.__current_target:
            print("Please use inspect to acquire a target!")
            return
        else:
            for pkt in self.__current_target.get_packets():
                print(pkt)
        return

    def get_pkt_target(self):
        if not self.__current_target:
            print("Please use inspect to acquire a target!")
            return
        else:
            check = True
            print("Please select packet by number:")
            print(self.__current_target.display_packet_summary())
            while(check):
                pkt_num = input("Select Packet >>>")
                if pkt_num.lower() == "back":
                    return
                if pkt_num.isnumeric() and int(pkt_num) >= 0 and int(pkt_num) < self.__current_target.get_repo_len():
                    print(self.__current_target.get_packet_by_num(int(pkt_num)))
                    check = False
                else:
                    print("Please select a number between 0 and ", self.__current_target.get_repo_len() - 1, ". Or type 'back'")
            return


if __name__ == "__main__":
    cl = CommandLine()