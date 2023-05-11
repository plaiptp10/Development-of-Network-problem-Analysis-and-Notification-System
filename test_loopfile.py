import pyshark
import os
from pathlib import Path
import time

while 1:

    folder = "pcap"
    dl = os.listdir(folder)
    print(dl)

    num_file = 0

    for file in dl:
        cap_t = pyshark.FileCapture("pcap/"+file, display_filter='http')
        num_file += 1
        print(num_file)
        # if file == dl[-1]:
        #     time.sleep(25)
        os.remove("pcap/"+file)
    if len(dl) == 0:
        break

# count = 0
# if len()
# for i in cap_t:
#     count += 1
# print(count)

# cap_t = pyshark.FileCapture(
#     "pcap/http_00010_20221114193922")
# num_file += 1
# print(num_file)
# packetcount = sum(1 for _ in cap_t)
# print(packetcount)
