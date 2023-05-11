import pyshark

cap_t = pyshark.FileCapture('icmp.pcap', display_filter='icmp')
count = 0
pkt_reply = []
pkt_req = []
pkt_loss = []
match = 0
count = 0
#แยก req, resp
print(dir(cap_t[0]))
for i in cap_t:
    count += 1
    if i.icmp.type == '0': #type 0 = Echo reply
        pkt_reply.append(i)
        print(i.length)
    elif i.icmp.type == '8': #type 8 = Echo request
        pkt_req.append(i)
    else:
        pkt_loss.append(i)

#หาคู่
loss = len(pkt_loss)
for i in pkt_req:
    for j in pkt_reply:
        # delay = j.icmp.resptime
        # print("Delay = %s" %delay)
        if i.icmp.seq == j.icmp.seq:
            match += 1
            break

print("Total Packet = %d" %count)
print("Packet Request = %d" %len(pkt_req))
print("Packet Reply = %d" %len(pkt_reply))
print("Loss = %d" %loss)
print("Match = %d"%match)