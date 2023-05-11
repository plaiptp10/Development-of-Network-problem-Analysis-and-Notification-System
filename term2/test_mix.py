from multiprocessing.resource_sharer import stop
import pyshark
import xlwt
from xlwt import Workbook
import matplotlib.pyplot as plt
from PIL import Image
import csv
import matplotlib
import numpy as np
import requests
from plyer import notification
import os
from pathlib import Path
import time
import schedule


def capture_live_packets(network_interface):
    # capture = pyshark.LiveCapture(
    #     interface=network_interface, display_filter='http.request.method == "GET" || http.response.code!=0')
    cap = pyshark.LiveCapture(
        interface=network_interface, display_filter='http.request.method == "GET" || http.response.code!=0')

    # define value
    matchcount = 0
    nxtseq = []
    ack = []
    request_number = []
    response_number = []
    size = []
    request_uri = []
    respose_uri = []
    size_request = []
    size_respose = []
    avg_size_total = 0
    delay = []
    avg_delay = 0.0
    num_lost = 0
    number_packet = []
    totalpacket = 0
    starttime = time.time()
    lasttime = starttime
    lapnum = 1

    # line notification
    url = 'https://notify-api.line.me/api/notify'
    token = '51P7BCktFo6YszYxIhQGFN1mKnGPLT6YYBNUtSJNTsC'
    headers = {'content-type': 'application/x-www-form-urlencoded',
               'Authorization': 'Bearer '+token}
    # หาค่า next sequence number และ ackknowledgment number เพื่อหาคู่ที่ match / หา size ของ packet
    for packet in cap.sniff_continuously():
        def testing():
            print(delay)
        schedule.every(0.1).minutes.do(testing)
        while True:
            # Checks whether a scheduled task
            # is pending to run or not
            schedule.run_pending()
            break
        if packet[packet.transport_layer].dstport == '80' or packet[packet.transport_layer].srcport == '80':
            # request
            if packet[packet.transport_layer].dstport == '80':
                nxtseq.append(packet.tcp.nxtseq)
                request_uri.append(packet.http.request_full_uri)
                request_number.append(packet.http.request_number)
                print("request")
            # response
            elif packet[packet.transport_layer].srcport == '80':
                ack.append(packet.tcp.ack)
                respose_uri.append(packet.http.response_for_uri)
                response_number.append(packet.http.response_number)
                delay.append(float(packet.http.time))
                print("response")
    # หาขนาดของ request packet
        size.append(float(packet.length))
        size_request.append(packet.length)
    # หาค่า delay ของ packet และแจ้งเตือนผ่านไลน์และหนัาจอคอม หาขนาดของ respose packet
        size.append(float(packet.length))
        size_respose.append(packet.length)
        if packet[packet.transport_layer].srcport == '80' and float(packet.http.time) >= 0.3:
            msg = 'Delay!!!!'
            r = requests.post(url, headers=headers, data={'message': msg})
            print(r.text)
            notification.notify(
                title='Alert!!!',
                message='High Delay',
                app_icon="icon.ico",
                timeout=5,
            )


def work():
    # หาค่าเฉลี่ยของ delay
    for i in range(len(delay)):
        avg_delay += float(delay[i])
    avg_delay = avg_delay/len(delay)

    # # หาจำนวนที่ match และ lost
    # for i in range(0, len(nxtseq)):
    #     check_lost = 0
    #     for j in range(0, len(ack)):
    #         if nxtseq[i] == ack[j] and request_uri[i] == respose_uri[j]:
    #             matchcount += 1
    #             check_lost += 1
    #             break
    #     if check_lost == 0:
    #         num_lost += 1

    # avg_lost = num_lost/totalpacket
    print(avg_delay)
    # print(nxtseq)
    # print(ack)
    # print(request_uri)
    # print(respose_uri)


capture_live_packets('Ethernet')
