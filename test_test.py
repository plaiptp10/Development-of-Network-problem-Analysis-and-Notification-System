import pyshark

cap_t = pyshark.FileCapture(
    'pcap backup/test_00008_20221120112414')

for i in cap_t:
    if hasattr(i, 'tcp'):
        print(i)
# print(nxtseq)
# print(ack)
