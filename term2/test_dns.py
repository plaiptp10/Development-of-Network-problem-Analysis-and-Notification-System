import pyshark

cap = pyshark.LiveCapture(interface="Ethernet")
pkt_resp = []
pkt_req = []
match = 0
count = 0
old_resp = 0
# แยก req, resp
for packet in cap.sniff_continuously():
    if hasattr(packet, 'dns'):
        if packet[packet.transport_layer].dstport == '53' or packet[packet.transport_layer].srcport == '53' \
                or packet[packet.udp].dstport == '53' or packet[packet.udp].srcport == '53':
            try:
                if packet.dns.resp_name:
                    pkt_resp.append(packet)
                    count += 1
                    print(packet.dns)
            except AttributeError as e:
                # ignore packets that aren't DNS Response
                pkt_req.append(packet)
                count += 1
                print(packet.dns)
        # หาคู่
        for i in pkt_req:
            for j in pkt_resp:
                if i.dns.id == j.dns.id and len(pkt_resp) != old_resp:
                    match += 1
                    old_resp = len(pkt_resp)
                    break
        print(count)
        print(match)


# ----------------------------------------------------------------------------------

# import pyshark

# cap_t = pyshark.FileCapture('term2/dns.pcap', display_filter='dns')
# pkt_resp = []
# pkt_req = []
# match = 0
# count = 0
# #แยก req, resp
# for i in cap_t:
#     count += 1
#     try:
#         if i.dns.resp_name:
#             pkt_resp.append(i)
#             print(i.dns.time)
#             # print(i.dns.resp_name)
#     except AttributeError as e:
#         #ignore packets that aren't DNS Response
#         pkt_req.append(i)
# #หาคู่
# for i in pkt_req:
#     for j in pkt_resp:
#         if i.dns.id == j.dns.id:
#             match += 1
#             break
# print(cap_t[0].dns)
# print(match)5
