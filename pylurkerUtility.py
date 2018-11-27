import os
import os.path
import sys
import invade
import pylurker
import warnings
import fileManager
import pyshark
import asyncio

if not sys.warnoptions:
    warnings.simplefilter("ignore")

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
    """Command tool for running the main loop for commands"""
    def __init__(self):
        self.__hunter = pylurker.Hunter()
        self.__cap_mode = None
        self.__current_target = None
        self.__current_network = None
        self.__network_list = list()
        self.__pcap_files = list()
        self.__current_file = None
        self.__filman = fileManager.FileManager
        self.__input_string = ""
        self.__prompt_string = "PyLurker >>> "
        # List of commands
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
                        "[GetLayer]   | Get packets with specific layer",
                        "[CapPack]    | Show all packets in capture file",
                        "[TarPack]    | Show all packets of a target",
                        "[CapSave]    | Save the current .pcap file",
                        "[TarSave]    | Save target's packets to file",
                        "[LiveCap]    | Live capture on current network]",
                        "[Exit]       | To end program"]

        # Dictionary used to index commands to related functions
        self.__command_dict = {'list': self.display_commands, 'scan': self.get_networks,
                            'connect' : self.connect_networks, 'load': self.load_file,
                            'files': self.__filman.get_pcap_files, 'hunt': self.hunt_targets,
                            'show': self.show_targets, 'stats': self.show_stats,
                            'cappack': self.print_full, 'tarpack': self.print_tarpack,
                            'inspect': self.inspect_target, 'getpack': self.get_pkt_target,
                            'current': self.show_current, 'capsave': self.save_all,
                            'tarsave': self.save_target, 'livecap': self.live_cap,
                            'getlayer': self.display_layer}

        self.begin()

    # [List] - Simple print of all available commands
    def display_commands(self):
        print("\nCommand List:")
        for item in self.__options:
            print(item)
        print("")

    # [Scan] - This function uses the invade module which relies on subprocess to get available wifi networks
    def get_networks(self):
        self.__network_list = invade.getNetworkList()
        for i, net in enumerate(self.__network_list):
            print(i+1, " - ", net)

    # {Connect] was not able to finish this in time
    def connect_networks(self):
        print("Please choose network you wish to connect to:")
        # populate a local list
        net_list = invade.getNet()
        for i, net in enumerate(net_list):
            print(i, " - ", net)
        if(net_list):
            check = True
            while(check):
                net_num = input("Please select network >>>")
                if net_num == 'back':
                    return
                if net_num.isnumeric() and int(net_num) >= 0 and int(net_num) < len(net_list):
                    print("Connecting...")
                    if(not 'Security:   Open' in net_list[int(net_num)]):
                        # Strip the network name to connect to
                        invade.connect_network(net_list[int(net_num)])
                    else:
                        invade.connect_network(net_list[int(net_num)], False)
                    check = False
                else:
                    print("Please select a number between 1 and ", len(net_list) - 1, ". Or type 'back'")
            if(invade.internet_check()):
                print("Connected Successfully")
            else:
                print("Unsuccessful connection")
        return

    # Simple function to load a .pcap file from current directory
    def load_file(self):
        check = True
        #reset the hunters values
        self.__hunter.flush()
        print("\nPlease select file from list below:")
        #Access the filemanager
        self.__pcap_files = self.__filman.get_pcap_files(self)
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
        self.__hunter.load_cap_file(self.__current_file)
        print(self.__current_file + " is loaded and ready to go! Happy Hunting!")
        self.__cap_mode = "File"
        return

    # Save all packets to txt file
    def save_all(self):
        # verify that a pcap file has been loaded to save to txt file
        if self.__hunter.get_cap == None:
            print("No capture file has been analyzed yet")
            return
        #Begin loop for filename input
        check = True
        fileList = self.__filman.get_text_files(self)
        while(check):
            fileName = input("Please enter a file name >>>")
            if fileName.lower() == "back":
                return
            if fileName + ".txt" in fileList and fileName != "tempXYZ123456789.txt" and fileName.isalnum():
                ov = input("Type [Yes] to Overwrite >>>")
                if ov.lower() == 'back':
                    return
                elif(ov.lower() == 'yes'):
                    self.__filman.save(self, fileName, self.__hunter.get_cap())
                    print("File saved!")
                    return
            else:
                self.__filman.save(self, fileName, self.__hunter.get_cap())
                print("File saved!")
                return
        return

    # Save all packets associated with a specific target
    def save_target(self):
        if self.__current_target == None:
            print("No current target to save")
            return

        check = True
        fileList = self.__filman.get_text_files(self)
        while(check):
            fileName = input("Please enter a file name >>>")
            if fileName.lower() == "back":
                return
            if fileName + ".txt" in fileList and fileName != "tempXYZ123456789.txt":
                ov = input("Type [Yes] to Overwrite >>>")
                if ov.lower() == 'back':
                    return
                elif(ov.lower() == 'yes'):
                    self.__filman.save(self, fileName, self.__current_target.get_packets())
                    print("File saved!")
                    return
            else:
                self.__filman.save(self, fileName, self.__current_target.get_packets())
                print("File saved!")
                return
        return

    # function which sets the hunter object into motion of acquiring its target list
    def hunt_targets(self):
        if self.__hunter.get_cap() == None:
            print("No capture file loaded!")
            return
        print("\nBeginning Hunt")
        self.__hunter.acquire_targets(self.__cap_mode)
        print("\n   ", self.__hunter.get_target_total()," targets acquired!")
        return

    # Display a lsit of all current targets
    def show_targets(self):
        tempList = self.__hunter.get_mini_target_list()
        for i, tg in enumerate(tempList):
            print(i+1, "-", tg)
        print("")
    def show_stats(self):
        tempList = self.__hunter.get_target_list()
        for i, tg in enumerate(tempList):
            print(i+1, "-", tg)

    # main loop which asks for inputs associated with the command list
    def begin(self):
        exit_flag = False
        print(intro_string)
        while(not exit_flag):

            self.__input_string = input(self.__prompt_string)
            if(self.__input_string.lower() == "exit"):
                exit_flag = True
            if self.__input_string.lower() in self.__command_dict.keys():
                self.__command_dict[self.__input_string]()

    #calls on hunter object to print full cap file
    def print_full(self):
        self.__hunter.print_full_cap()

    # prints the current target
    def show_current(self):
        print(self.__current_target)

    # inspect target is how the current target variable in the command line object is populated
    def inspect_target(self):
        print("\nPlease select target from list below using associated number:")
        # Print a list of current objects
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

    # displays all packets associated with the current target
    def print_tarpack(self):
        if not self.__current_target:
            print("Please use inspect to acquire a target!")
            return
        else:
            for pkt in self.__current_target.get_packets():
                print(pkt)
        return

    # displays a simplified view of all packets by layers included
    # user picks a packet
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

    # Function has use select from a list of highest_layers and shows all packets associated with this highest layer
    def display_layer(self):
        if not self.__current_target:
            print("Please use inspect to acquire a target!")
            return
        else:
            check = True
            while(check):
                print("Please select layer type by number")
                for i, item in enumerate(self.__current_target.get_high_layers()):
                    print(i, " - ", item)
                lay_select = input("Please select a layer by number >>>")
                if(lay_select.lower() == 'back'):
                    return
                if lay_select.isnumeric() and int(lay_select) >= 0 and int(lay_select) < len(self.__current_target.get_high_layers()):
                    self.__current_target.print_lay_select(self.__current_target.get_high_layers()[int(lay_select)])
                    check = False
                else:
                    print("Please select a number between 0 and ", len(self.__current_target.get_high_layers() - 1, ". Or type 'back'"))
        return

    # live capture mode

    # VERY IMPORTANT:
    # in order work correctly you will need to open command line in adminstrator mode and type:
    #     'sc config npf start= auto'  .  Then restart computer this causes the netGroup packet
    #     filter to start up automatically
    def live_cap(self):
        check = True
        sniff_dur = 0
        #set the sniff duration for packet acquisition
        while(check):
            sniff_dur = input("Please choose sniff duration(choose between 5 to 100)")
            if(sniff_dur.isnumeric() and int(sniff_dur) >= 5 and int(sniff_dur) <= 100):
                check = False
        # Determine if internet filtering is required
        while(not check):
            net_filter = input("Filter only internet traffic? [Y/N]")
            if net_filter.lower() == 'n':
                print("Begin Live Capture - All")
                # flush the hunter's variables
                self.__hunter.flush()
                #https: // thepacketgeek.com / pyshark - filecapture - and -livecapture - modules /
                try:
                    cap = pyshark.LiveCapture(interface='Wi-Fi')
                    #cap.set_debug()
                    cap.sniff(timeout=int(sniff_dur))
                #https://github.com/aio-libs/aiohttp/issues/1207
                except asyncio.TimeoutError as e:
                    print("Async error Caught!")
                print("Live Capture Completed!")
                self.__hunter.load_cap_live(cap)
                print("Finished with live capture = ", cap)
                check = True
            elif net_filter.lower() == 'y':
                print("Beginning Live Capture - Internet Traffic Only")
                self.__hunter.flush()
                try:
                    cap = pyshark.LiveCapture(interface='Wi-Fi', bpf_filter='ip and tcp port 80')
                    #cap.set_debug()
                    cap.sniff(timeout=int(sniff_dur))
                #https://github.com/aio-libs/aiohttp/issues/1207
                #work around with the async error during live capture
                except asyncio.TimeoutError as e:
                    print("Async error Caught!")
                print("Live Capture Completed!")
                self.__hunter.load_cap_live(cap)
                print("Finished with live capture = ", cap)
                check = True
        self.__cap_mode = "Live"
        return

if __name__ == "__main__":
    cl = CommandLine()
