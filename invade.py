import subprocess

#ww = wireless.Wireless()

#https://stackoverflow.com/questions/31868486/list-all-wireless-networks-python-for-pc
def getNetworkList():
    results = subprocess.check_output(["netsh", "wlan", "show", "network"])
    results = results.decode('utf-8')
    results = results.split('\r\n')
    #print(results)
    nets = list()
    for item in results:
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

