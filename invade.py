import subprocess
from subprocess import Popen, STDOUT, PIPE
from time import sleep


# modulate used specifically to interact with sub process to acquire wifi information

# get a list of networks available in Wi-Fi
#https://stackoverflow.com/questions/31868486/list-all-wireless-networks-python-for-pc
def getNetworkList():
    results = subprocess.check_output(["netsh", "wlan", "show", "network"])
    results = results.decode('utf-8')
    results = results.split('\r\n')

    nets = list()
    for item in results:
        # Search for the SSID in the list
        if("SSID" in item):
            if(item.split(': ')[1] == ""):
                nt = "Network:   Hidden Network"
                nt.ljust(20)
                #nets.append("Network:   Hidden Network")
            else:
                nt = "Network:   " + item.split(': ')[1]
                nt.ljust(20)

        if("Auth" in item):
            st = "\n        * Security:   " + item.split(': ')[1]
            total = nt + st
            nets.append(total)
    return nets

# return a list of the networks but name only
def getNet():
    results = subprocess.check_output(["netsh", "wlan", "show", "network"])
    results = results.decode('utf-8')
    results = results.split('\r\n')
    nets = list()
    for item in results:
        if("SSID" in item):
            if(item.split(': ')[1] == ""):
                nets.append("Hidden Network")
            else:
                nets.append(item.split(': ')[1])
    return nets

# connect to network by selection
#https://stackoverflow.com/questions/18227479/connection-to-wi-fi-using-python
def connect_network(wifi_name, password=True):
    if password:
        comm = 'netsh wlan connect ' + wifi_name
        handle = Popen(comm, shell=True, stdout=PIPE, stderr=STDOUT, stdin=PIPE)
        print("Connected to ", wifi_name)
        sleep(5) # wait for the password prompt to occur (if there is one, i'm on Linux and sudo will always ask me for a password so i'm just assuming windows isn't retarded).
        pw = input("Please type password:")
        #Popen(pw, shell=True, stdout=PIPE, stderr=STDOUT, stdin=PIPE)
        handle.stdin.write(pw.encode('utf-8'))
        while handle.poll() == None:
            print(handle.stdout.readline().strip())
    else:
        comm = 'netsh wlan connect ' + wifi_name
        handle = Popen(comm, shell=True, stdout=PIPE, stderr=STDOUT, stdin=PIPE)

# simple check is internet is available
#https://stackoverflow.com/questions/3764291/checking-network-connection
def internet_check():
    try:
        import httplib
    except:
        import http.client as httplib


    conn = httplib.HTTPConnection("www.google.com", timeout=5)
    try:
        conn.request("HEAD", "/")
        conn.close()
        return True
    except:
        conn.close()
        return False