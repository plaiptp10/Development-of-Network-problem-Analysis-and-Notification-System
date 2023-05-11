import pyshark
import os
from pathlib import Path

folder = "pcap"
dl = os.listdir(folder)
num_file = 0

if os.path.isdir("pcap"):
    print("1")

    # for file in dl:
    #     cap_t = pyshark.FileCapture("pcap/"+file, display_filter='http')
    #     num_file += 1
    #     print(num_file)
    #     packetcount = sum(1 for _ in cap_t)
    #     print(packetcount)
    #     os.remove("pcap/"+file)
