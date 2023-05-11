import pyshark


def capture_live_packets(network_interface):
    # capture = pyshark.LiveCapture(
    #     interface=network_interface, display_filter='http.request.method == "GET" || http.response.code!=0')
    capture = pyshark.LiveCapture(
        interface=network_interface)
    nxtseq = []
    ack = []
    # LiveCapture = 0

    for packet in capture.sniff_continuously():
        try:
            if hasattr(packet, 'tcp'):
                nxtseq.append(packet.tcp.nxtseq)
                ack.append(packet.tcp.ack)
                print(packet)
        except KeyboardInterrupt:
            pass
        # try:
        # print('Source = ' + packet['ip'].src)
        # print('Destination =' + packet['ip'].dst)
        # print(filter_all_tcp_traffic_file(packet))
        # print(packet.tcp.time_delta)
        # if hasattr(packet, 'tcp') and packet[packet.transport_layer].dstport == '80':
        # results = get_packet_details(packet)
        # return results
        # print(packet)
        # if hasattr(packet, 'tcp'):
        # results = get_packet_details(packet)
        # print(packet)
        # LiveCapture += 1
        print(nxtseq)
        print(ack)


capture_live_packets('Ethernet')
