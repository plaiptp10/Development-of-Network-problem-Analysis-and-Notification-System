import pyshark

cap_t = pyshark.FileCapture('http.pcap', display_filter='tcp')
count = 0
pkt_resp = []
pkt_req = []
match = 0
count = 0
#แยก req, resp
for i in cap_t:
    count += 1
    try:
        if i.tcp.analysis_ack_rtt:
            pkt_resp.append(i)
            print(i.tcp)
    except AttributeError as e:
        #ถ้าไม่ใช่ Response
        pkt_req.append(i)
        # print(i.tcp)

#หาคู่
for i in pkt_req:
    for j in pkt_resp:
        if i.tcp.ack == j.tcp.nxtseq and i.tcp.dstport == j.tcp.srcport:
            match += 1
            break

print(count)
print(len(pkt_req))
print(len(pkt_resp))
print(match)