import wifi

import subprocess

import wifi
import wireless

def Search():
    wifilist = []

    cells = wifi.Cell.all('wlan0')

    for cell in cells:
        wifilist.append(cell)

    return wifilist


def FindFromSearchList(ssid):
    wifilist = Search()

    for cell in wifilist:
        if cell.ssid == ssid:
            return cell

    return False


def FindFromSavedList(ssid):
    cell = wifi.Scheme.find('wlan0', ssid)

    if cell:
        return cell

    return False


def Connect(ssid, password=None):
    cell = FindFromSearchList(ssid)

    if cell:
        savedcell = FindFromSavedList(cell.ssid)

        # Already Saved from Setting
        if savedcell:
            savedcell.activate()
            return cell

        # First time to conenct
        else:
            if cell.encrypted:
                if password:
                    scheme = Add(cell, password)

                    try:
                        scheme.activate()

                    # Wrong Password
                    except wifi.exceptions.ConnectionError:
                        Delete(ssid)
                        return False

                    return cell
                else:
                    return False
            else:
                scheme = Add(cell)

                try:
                    scheme.activate()
                except wifi.exceptions.ConnectionError:
                    Delete(ssid)
                    return False

                return cell

    return False


def Add(cell, password=None):
    if not cell:
        return False

    scheme = wifi.Scheme.for_cell('wlan0', cell.ssid, cell, password)
    scheme.save()
    return scheme


def Delete(ssid):
    if not ssid:
        return False

    cell = FindFromSavedList(ssid)

    if cell:
        cell.delete()
        return True

    return False



#ww = wireless.Wireless()

#https://stackoverflow.com/questions/31868486/list-all-wireless-networks-python-for-pc
def getNetworkList():
    results = subprocess.check_output(["netsh", "wlan", "show", "network"])
    results = results.decode('utf-8')
    results = results.split('\r\n')
    print(results)
    nets = list()
    for item in results:
        if("SSID" in item):
            nets.append(item.split(': ')[1])
    return nets

print(getNetworkList())
connectCheck = False
#nw = nets[0]
password = '2037290809'
inter = 'Wireless Network Connection'
#" interface="' + inter + '"'
#https://www.techworm.net/2016/10/connect-manage-delete-wi-fi-networks-using-command-prompt.html
#while(not connectCheck):
#NETSH WLAN SET HOSTEDNETWORK MODE=ALLOW SSID=”YOUR WIFI CONNECTION NAME” KEY=”YOUR WIFI CONNECTION PASSWORD”
network = subprocess.Popen('netsh wlan hostednetwork mode=allow ssid="Router? But I hardly know her." key="2037290809"',shell=True)
#network = subprocess.Popen('netsh wlan connect ssid="' + str(nw) + '"', shell=True)
#network.communicate(input=password.encode('utf-8'))
#network.stdin.close()

#connect_result = subprocess.getoutput("netsh" "wlan" "set" "hostednetwork" "mode=allow" nw password)
    #"NETSH WLAN SET HOSTEDNETWORK MODE=ALLOW SSID=”YOUR WIFI CONNECTION NAME” KEY=”YOUR WIFI CONNECTION PASSWORD”
#print(connect_result)

#)


#ww = wireless.Wireless()


#if __name__ == '__main__':
    # Search WiFi and return WiFi list
    #print(Search())

    # Connect WiFi with password & without password
    #print
    #Connect('OpenWiFi')
    #print
    #Connect('ClosedWiFi', 'password')

    # Delete WiFi from auto connect list
    #print
    #Delete('DeleteWiFi')