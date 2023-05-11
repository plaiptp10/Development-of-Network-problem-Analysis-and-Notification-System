import pyshark
import os
from pathlib import Path

# folder = "pcap"
# dl = os.listdir(folder)
# print(dl)

# for file in dl:
#     cap_t = pyshark.FileCapture(file, display_filter='http')

# my_file = Path("pcap/httpcapturetest_00001_20221114173448")

# if my_file.is_file():
#     print("1")
# else:
#     print("0")

# cap_t = pyshark.FileCapture(
#     'pcap backup/test_00008_20221120112414', display_filter='http')
cap_req = pyshark.FileCapture(
    'pcap backup/test_00008_20221120112414', display_filter='http.request.method == "GET"')
cap_res = pyshark.FileCapture(
    'pcap backup/test_00008_20221120112414', display_filter='http.response.code!=0')
# packet_count = sum(1 for _ in cap_t)
count = 0
size = []
minsize = 0
nxtseq = []
ack = []
request_uri = []
respose_uri = []
matchcount = 0
# print(sum(1 for _ in cap_t))
# print(sum(1 for _ in cap_req))
# print(dir(cap_req[0]))
# print(cap_req[0])
# print(cap_res[0])
# for packet in cap_req:
#     size.append(packet.length)
# for packet in cap_res:
#     size.append(int(packet.length))
# size.sort()
# print(size[1])
# print(size)
# print(max(size))
# print(sum(1 for _ in cap_res))
# for i in cap_res:
#     print(i.http)
# print(cap_res[0].http.response_number)
print(dir(cap_req[0].http))
# for i in cap_t:
#     print(i.http)
#     count += 1
#     # test1.append(i.http.request_full_uri)
#     # for i in cap_res:
#     # test2.append(i.http.response_for_uri)
#     # print(i.http.request_in)
#     print(i.tcp)
#     print(i.http)
#     # print(dir(i.http))
# for packet in cap_req:
#     print(packet.http)
#     nxtseq.append(packet.tcp.nxtseq)
#     request_uri.append(packet.http.request_full_uri)
# for packet in cap_res:
#     print(packet.http)
#     print(packet.http)
#     count += 1
# print(packet.http.respose_for_uri)
# for i in range(1):
#     print(cap_res[1].http)
# if
# try:
#     x = packet.http.time
#     print("+")
# except AttributeError:
#     print("-")
#     count += 1
#     ack.append(packet.tcp.ack)
#     respose_uri.append(packet.http.response_for_uri)
# for i in range(0, len(nxtseq)):
#     for j in range(0, len(ack)):
#         # if nxtseq[i] == ack[j] and request_uri[i] == respose_uri[j]:
#         if nxtseq[i] == ack[j]:
#             matchcount += 1
#             break

# print(nxtseq, request_uri)
# print(ack, respose_uri)
# for i, j in matchpacket_request.items():
#     print(i, j)

# print(test1)
# print(test2)
# print(nxtseq)
# print(ack)
# print(matchpacket_request)
# print(matchpacket_respose)
print(count)
# print(packetcount)
# print("Total packet : " + str(packet_count))
# filter_request_response()


# def filter_request_response():
# cap_request = pyshark.FileCapture(
#     'http.pcap', display_filter='http.request.method')
# cap_response = pyshark.FileCapture(
#     'http.pcap', display_filter='http.response.code!=200')
# count_request = 0
# count_response = 0
# time_response = []
# # time_average = 0
# for i in cap_request:
#     count_request += 1
# for i in cap_response:
#     count_response += 1
#     time_response.append(i.http.time)
#     # time_average += i.http.time
# print("http request : " + str(count_request))
# print("http response : " + str(count_response))
# print(time_response)
