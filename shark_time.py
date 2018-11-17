import pyshark


cap = pyshark.FileCapture('mult2.pcap')

for pkt in cap:
    try:

        print(pkt.bootp.field_names)
        print(pkt.bootp.option_hostname)
        #print(pkt.bootp['id'])
    except AttributeError:
        pass
