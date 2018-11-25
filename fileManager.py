import os

class FileManager():
    def __init(self):
        current_directory = os.curdir

    def get_pcap_files(self):
        fileList = list()
        fileList.extend([f for f in os.listdir(os.curdir) if f.endswith('.pcap')])
        print("\nPCAP Files in current directory:")
        for f in fileList:
            #https: // stackoverflow.com / questions / 2104080 / how - to - check - file - size - in -python
            print(f, "   File Size: ", round(os.path.getsize(f) / 1048576, 1), "MB")
        print("")
        return fileList


    def get_text_files(self):
        fileList = list()
        fileList.extend([f for f in os.listdir(os.curdir) if f.endswith('.txt')])
        print("\nText Files in current directory:")
        for f in fileList:
            #https: // stackoverflow.com / questions / 2104080 / how - to - check - file - size - in -python
            print(f, "   File Size: ", round(os.path.getsize(f) / 1048576, 1), "MB")
        print("")
        return fileList

    def save(self, name, file):
        txt = name + ".txt"
        f = open(txt, "w")
        for pkt in file:
            f.write(str(pkt))
        f.close()
        """
        tf = open('tempXYZ123456789.txt', "w")
        for pkt in file:
            tf.write(str(pkt).strip("\r"))
        tf.close()
        f = open(txt, "w")
        rf = open("tempXYZ123456789.txt")
        for line in rf:
            newline = line.rstrip("\n")
            f.write(newline)
            #f.write("\n")
        rf.close()
        f.close()
        os.remove("tempXYZ123456789.txt")
        """