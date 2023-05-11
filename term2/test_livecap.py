import pyshark


def filter_https_live_packet_capture(packet):
    if hasattr(packet, 'tcp') and packet[packet.transport_layer].dstport == '443':
        results = get_packet_details(packet)
        return results


def filter_http_live_packet_capture(packet):
    if hasattr(packet, 'tcp') and packet[packet.transport_layer].dstport == '80':
        results = get_packet_details(packet)
        return results


def filter_all_tcp_traffic_file(packet):
    if hasattr(packet, 'tcp'):
        results = get_packet_details(packet)
        return results


def filter_all_web_traffic_file(packet):
    if hasattr(packet, 'tcp'):
        if packet[packet.transport_layer].dstport == '80' or packet[packet.transport_layer].dstport == '443':
            results = get_packet_details(packet)
            return results


def get_packet_details(packet):
    protocol = packet.transport_layer
    source_address = packet.ip.src
    source_port = packet[packet.transport_layer].srcport
    destination_address = packet.ip.dst
    destination_port = packet[packet.transport_layer].dstport
    packet_time = packet.sniff_time
    return f'Packet Timestamp: {packet_time}' \
           f'\nProtocol type: {protocol}' \
           f'\nSource address: {source_address}' \
           f'\nSource port: {source_port}' \
           f'\nDestination address: {destination_address}' \
           f'\nDestination port: {destination_port}\n'


def get_live_captures(parse_type, network_interface):
    capture = pyshark.LiveCapture(interface=network_interface)
    # capture.sniff(timeout=50)
    for raw_packet in capture.sniff_continuously():
        if parse_type is 'https':
            results = filter_https_live_packet_capture(raw_packet)
            if results is not None:
                print(results)
        elif parse_type is 'http':
            results = filter_http_live_packet_capture(raw_packet)
            if results is not None:
                print(results)
        elif parse_type is 'tcp':
            results = filter_all_tcp_traffic_file(raw_packet)
            if results is not None:
                print(results)
        elif parse_type is 'web':
            results = filter_all_web_traffic_file(raw_packet)
            if results is not None:
                print(results)


def main():

    # PCAP file to parse
    pcap_file = 'file name .pcap'

    # Network interface used by TShark for live capture
    network_interface = 'Ethernet'

    # Parse types include: tcp, udp, dns, ftp, http, https,
    # netbios, ssh, web (which includes http & https)
    # get_file_captures('http', pcap_file)

    # Parse types include: dns, ftp, http, https,
    # ssh, web (which includes http & https)
    get_live_captures('tcp', network_interface)

    # Parse types include: file and live.
    # get_retransmissions('file', pcap_file, network_interface)

    # Prases all the Uniform Resource Locators (URLs) from
    # a PCAP file.
    # get_urls_file_captures(pcap_file)


main()
