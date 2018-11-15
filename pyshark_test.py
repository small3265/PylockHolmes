import sys
import pyshark
import pylurker

print("hi")
def print_conversation_header(pkt):
    try:
        protocol = pkt.transport_layer
        src_addr = pkt.ip.src
        src_port = pkt[pkt.transport_layer].srcport
        dst_addr = pkt.ip.dst
        dst_port = pkt[pkt.transport_layer].dstport
        print(protocol + " : " + src_addr + " " + src_port + " --> " + dst_addr + " " + dst_port)
    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        pass

mv = pylurker.load_MAC_Vendor()

ipList = list()
vendList = list()
#print(mv)
cap = pyshark.FileCapture('mult2.pcap')
print(cap[0].layers)
for pkt in cap:
    #print(pkt)
    #print_conversation_header(pkt)
    #print(cap[i].ip.src)
    #ipList.append(cap[i].ip.src)
    macString = str(pkt.eth.src).replace(':', '').upper()[0:6]
    if macString in mv.keys() and not macString in vendList:
        print(mv[macString])
        vendList.append(macString)
    elif not macString in mv.keys() and not macString in vendList:
        print(macString + " = Unknown vendor")
        vendList.append(macString)
    #break

#print(ipList)
exit()


sys.exit()
#cap.apply_on_packets(print_conversation_header, timeout=1)