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
import datetime
import schedule
from threading import Thread
from fpdf import FPDF
from email.message import EmailMessage
import ssl
import smtplib
from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
import configparser
import json

# define value
matchcount = 0
nxtseq = []
ack = []
request_number = []
response_number = []
size = []
request_uri = []
response_uri = []
size_request = []
size_response = []
avg_size_total = 0
delay = []
avg_delay = 0.0
num_lost = 0
number_packet = []
totalpacket = 0
starttime = time.time()
lasttime = starttime
lapnum = 1
old_ack = 0
avg_lost = 0
x = 0
receiver = []
pkt_resp = []
pkt_req = []
old_resp = 0


def capture_live_packets(parse_type, network_interface):
    cap = pyshark.LiveCapture(interface=network_interface)
    schedule.every(1).minutes.do(result) #ตั้งเวลาในการสรุปข้อมูลออกมาเป็บไฟล์ seconds/minutes/hours/days
    for packet in cap.sniff_continuously():
        schedule.run_pending()
        if parse_type == 'http':
            filter_http_live_packet(packet)
        elif parse_type == 'dns':
            filter_dns_live_packet(packet)
        elif parse_type == 'tcp':
            filter_tcp_live_packet(packet)
        elif parse_type == 'icmp':
            filter_icmp_live_packet(packet)


def capture_file_packets(parse_type, pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    for packet in capture:
        if parse_type == 'http':
            filter_http_file_packet(packet)
        elif parse_type == 'dns':
            filter_dns_file_packet(packet)
        elif parse_type == 'tcp':
            filter_tcp_file_packet(packet)
        elif parse_type == 'icmp':
            filter_icmp_file_packet(packet)
    result()


def filter_http_live_packet(packet):
    global matchcount, nxtseq, ack, size, request_uri, response_uri, delay, num_lost, avg_delay, old_ack, avg_lost, avg_size_total, totalpacket
    # line notification
    url = 'https://notify-api.line.me/api/notify'
    token = '51P7BCktFo6YszYxIhQGFN1mKnGPLT6YYBNUtSJNTsC'
    headers = {'content-type': 'application/x-www-form-urlencoded',
               'Authorization': 'Bearer '+token}
    if hasattr(packet, 'http'):
        # request
        if packet[packet.transport_layer].dstport == '80':
            nxtseq.append(packet.tcp.nxtseq)
            request_uri.append(packet.http.request_full_uri)
            request_number.append(packet.http.request_number)
            size_request.append(packet.length)
            size.append(float(packet.length))
            totalpacket += 1
            print('request')
        # response
        elif packet[packet.transport_layer].srcport == '80':
            ack.append(packet.tcp.ack)
            response_uri.append(packet.http.response_for_uri)
            response_number.append(packet.http.response_number)
            size_response.append(packet.length)
            size.append(float(packet.length))
            totalpacket += 1
            print('response')
            delay.append(float(packet.http.time))
            if float(packet.http.time) >= 0.3:
                msg = 'Delay!!!!'
                r = requests.post(url, headers=headers,
                                  data={'message': msg})
                print(r.text)
                notification.notify(
                    title='Alert!!!',
                    message='High Delay',
                    app_icon="icon.ico",
                    timeout=5,
                )
                send_alert(receiver, "Delay is too high!")
        # หาค่าเฉลี่ยของ size ทั้งหมด
        for i in range(len(size)):
            avg_size_total += float(size[i])
        if len(size) != 0:
            avg_size_total = avg_size_total/len(size)
        # หาค่าเฉลี่ยของ delay
        for i in range(len(delay)):
            avg_delay += float(delay[i])
        if len(delay) != 0:
            avg_delay = avg_delay/len(delay)
        # หาจำนวนที่ match และ lost
        for i in range(0, len(nxtseq)):
            for j in range(0, len(ack)):
                if nxtseq[i] == ack[j] and request_uri[i] == response_uri[j]:
                    if len(ack) != old_ack:
                        matchcount += 1
                        old_ack = len(ack)
                        break
                    else:
                        continue
        num_lost = totalpacket-(matchcount*2)
        if totalpacket != 0:
            avg_lost = num_lost/totalpacket


def filter_dns_live_packet(packet):
    global matchcount, size, delay, num_lost, avg_delay, avg_lost, avg_size_total, totalpacket, pkt_resp, pkt_req, old_resp
    url = 'https://notify-api.line.me/api/notify'
    token = '51P7BCktFo6YszYxIhQGFN1mKnGPLT6YYBNUtSJNTsC'
    headers = {'content-type': 'application/x-www-form-urlencoded',
               'Authorization': 'Bearer '+token}
    if hasattr(packet, 'dns'):
        if packet[packet.transport_layer].dstport == '53' or packet[packet.transport_layer].srcport == '53' \
                or packet[packet.udp].dstport == '53' or packet[packet.udp].srcport == '53':
            try:
                if packet.dns.resp_name:  # response
                    pkt_resp.append(packet)
                    size_response.append(packet.length)
                    size.append(float(packet.length))
                    delay.append(float(packet.dns.time))
                    totalpacket += 1
                    print('response')
                    if float(packet.dns.time) >= 0.3:
                        msg = 'Delay!!!!'
                        r = requests.post(url, headers=headers,
                                          data={'message': msg})
                        print(r.text)
                        notification.notify(
                            title='Alert!!!',
                            message='High Delay',
                            app_icon="icon.ico",
                            timeout=5,
                        )
                        send_alert(receiver, "Delay is too high!")
            except AttributeError as e:  # request
                # ignore packets that aren't DNS Response
                pkt_req.append(packet)
                size_request.append(packet.length)
                size.append(float(packet.length))
                totalpacket += 1
                print('request')
        # หาค่าเฉลี่ยของ size ทั้งหมด
        for i in range(len(size)):
            avg_size_total += float(size[i])
        if len(size) != 0:
            avg_size_total = avg_size_total/len(size)
        # หาค่าเฉลี่ยของ delay
        for i in range(len(delay)):
            avg_delay += float(delay[i])
        if len(delay) != 0:
            avg_delay = avg_delay/len(delay)
        # หาคู่
        for i in pkt_req:
            for j in pkt_resp:
                if i.dns.id == j.dns.id and len(pkt_resp) != old_resp:
                    matchcount += 1
                    old_resp = len(pkt_resp)
                    break
        num_lost = totalpacket-(matchcount*2)
        if totalpacket != 0:
            avg_lost = num_lost/totalpacket


def filter_icmp_live_packet(packet):
    global matchcount, size, delay, num_lost, avg_delay, avg_lost, avg_size_total, totalpacket, pkt_resp, pkt_req, old_resp
    url = 'https://notify-api.line.me/api/notify'
    token = '51P7BCktFo6YszYxIhQGFN1mKnGPLT6YYBNUtSJNTsC'
    headers = {'content-type': 'application/x-www-form-urlencoded',
               'Authorization': 'Bearer '+token}
    if hasattr(packet, 'icmp'):
        if packet.icmp.type == '0':  # type 0 = Echo reply
            totalpacket += 1
            pkt_resp.append(packet)
            size_response.append(packet.length)
            size.append(float(packet.length))
            delay.append(float(packet.icmp.resptime))
            print('response')
            if float(packet.icmp.resptime) >= 0.3:
                msg = 'Delay!!!!'
                r = requests.post(url, headers=headers,
                                  data={'message': msg})
                print(r.text)
                notification.notify(
                    title='Alert!!!',
                    message='High Delay',
                    app_icon="icon.ico",
                    timeout=5,
                )
                send_alert(receiver, "Delay is too high!")
        elif packet.icmp.type == '8':  # type 8 = Echo request
            totalpacket += 1
            pkt_req.append(packet)
            size_request.append(packet.length)
            size.append(float(packet.length))
            print('request')
        # หาค่าเฉลี่ยของ size ทั้งหมด
        for i in range(len(size)):
            avg_size_total += float(size[i])
        if len(size) != 0:
            avg_size_total = avg_size_total/len(size)
        # หาค่าเฉลี่ยของ delay
        for i in range(len(delay)):
            avg_delay += float(delay[i])
        if len(delay) != 0:
            avg_delay = avg_delay/len(delay)
        # หาคู่
        for i in pkt_req:
            for j in pkt_resp:
                if i.icmp.seq == j.icmp.seq and len(pkt_resp) != old_resp:
                    matchcount += 1
                    old_resp = len(pkt_resp)
                    break
        num_lost = totalpacket-(matchcount*2)
        if totalpacket != 0:
            avg_lost = num_lost/totalpacket


def filter_tcp_live_packet(packet):
    global matchcount, size, delay, num_lost, avg_delay, avg_lost, avg_size_total, totalpacket, pkt_resp, pkt_req, old_resp
    url = 'https://notify-api.line.me/api/notify'
    token = '51P7BCktFo6YszYxIhQGFN1mKnGPLT6YYBNUtSJNTsC'
    headers = {'content-type': 'application/x-www-form-urlencoded',
               'Authorization': 'Bearer '+token}
    if hasattr(packet, 'tcp'):
        try:
            if packet.tcp.analysis_ack_rtt:
                totalpacket += 1
                pkt_resp.append(packet)
                size_response.append(packet.length)
                size.append(float(packet.length))
                delay.append(float(packet.tcp.analysis_ack_rtt))
                print('response')
                if float(packet.tcp.analysis_ack_rtt) >= 0.3:
                    msg = 'Delay!!!!'
                    r = requests.post(url, headers=headers,
                                      data={'message': msg})
                    print(r.text)
                    notification.notify(
                        title='Alert!!!',
                        message='High Delay',
                        app_icon="icon.ico",
                        timeout=5,
                    )
                    send_alert(receiver, "Delay is too high!")
        except AttributeError as e:
            # ถ้าไม่ใช่ Response
            totalpacket += 1
            pkt_req.append(packet)
            size_request.append(packet.length)
            size.append(float(packet.length))
            print('request')
        # หาค่าเฉลี่ยของ size ทั้งหมด
        for i in range(len(size)):
            avg_size_total += float(size[i])
        if len(size) != 0:
            avg_size_total = avg_size_total/len(size)
        # หาค่าเฉลี่ยของ delay
        for i in range(len(delay)):
            avg_delay += float(delay[i])
        if len(delay) != 0:
            avg_delay = avg_delay/len(delay)
        # หาคู่
        for i in pkt_req:
            for j in pkt_resp:
                if (i.tcp.ack == j.tcp.nxtseq and i.tcp.dstport == j.tcp.srcport) and len(pkt_resp) != old_resp:
                    matchcount += 1
                    old_resp = len(pkt_resp)
                    break
        num_lost = totalpacket-(matchcount*2)
        if totalpacket != 0:
            avg_lost = num_lost/totalpacket


def filter_http_file_packet(packet):
    global matchcount, nxtseq, ack, size, request_uri, response_uri, delay, num_lost, avg_delay, old_ack, avg_lost, avg_size_total, totalpacket
    # line notification
    url = 'https://notify-api.line.me/api/notify'
    token = '51P7BCktFo6YszYxIhQGFN1mKnGPLT6YYBNUtSJNTsC'
    headers = {'content-type': 'application/x-www-form-urlencoded',
               'Authorization': 'Bearer '+token}

    if hasattr(packet, 'http'):
        # request
        if packet[packet.transport_layer].dstport == '80':
            nxtseq.append(packet.tcp.nxtseq)
            request_uri.append(packet.http.request_full_uri)
            request_number.append(packet.http.request_number)
            size_request.append(packet.length)
            size.append(float(packet.length))
            totalpacket += 1
            print('request')
        # response
        elif packet[packet.transport_layer].srcport == '80':
            ack.append(packet.tcp.ack)
            response_uri.append(packet.http.response_for_uri)
            response_number.append(packet.http.response_number)
            size_response.append(packet.length)
            size.append(float(packet.length))
            totalpacket += 1
            print('response')
            delay.append(float(packet.http.time))
            if float(packet.http.time) >= 0.3:
                msg = 'Delay!!!!'
                r = requests.post(url, headers=headers,
                                  data={'message': msg})
                print(r.text)
                notification.notify(
                    title='Alert!!!',
                    message='High Delay',
                    app_icon="icon.ico",
                    timeout=5,
                )
                send_alert(receiver, "Delay is too high!")
        # หาค่าเฉลี่ยของ size ทั้งหมด
        for i in range(len(size)):
            avg_size_total += float(size[i])
        if len(size) != 0:
            avg_size_total = avg_size_total/len(size)
        # หาค่าเฉลี่ยของ delay
        for i in range(len(delay)):
            avg_delay += float(delay[i])
        if len(delay) != 0:
            avg_delay = avg_delay/len(delay)
        # หาจำนวนที่ match และ lost
        for i in range(0, len(nxtseq)):
            for j in range(0, len(ack)):
                if nxtseq[i] == ack[j] and request_uri[i] == response_uri[j]:
                    if len(ack) != old_ack:
                        matchcount += 1
                        old_ack = len(ack)
                        break
                    else:
                        continue
        num_lost = totalpacket-(matchcount*2)
        if totalpacket != 0:
            avg_lost = num_lost/totalpacket


def filter_dns_file_packet(packet):
    global matchcount, size, delay, num_lost, avg_delay, avg_lost, avg_size_total, totalpacket, pkt_resp, pkt_req, old_resp
    url = 'https://notify-api.line.me/api/notify'
    token = '51P7BCktFo6YszYxIhQGFN1mKnGPLT6YYBNUtSJNTsC'
    headers = {'content-type': 'application/x-www-form-urlencoded',
               'Authorization': 'Bearer '+token}
    if hasattr(packet, 'dns'):
        if packet[packet.transport_layer].dstport == '53' or packet[packet.transport_layer].srcport == '53' \
                or packet[packet.udp].dstport == '53' or packet[packet.udp].srcport == '53':
            try:
                if packet.dns.resp_name:  # response
                    pkt_resp.append(packet)
                    size_response.append(packet.length)
                    size.append(float(packet.length))
                    delay.append(float(packet.dns.time))
                    totalpacket += 1
                    # print('response')
                    print(packet.dns.time)
                    if float(packet.dns.time) >= 0.05:
                        msg = 'Delay!!!!'
                        r = requests.post(url, headers=headers,
                                          data={'message': msg})
                        print(r.text)
                        notification.notify(
                            title='Alert!!!',
                            message='High Delay',
                            app_icon="icon.ico",
                            timeout=5,
                        )
                        send_alert(receiver, "Delay is too high!")
            except AttributeError as e:  # request
                # ignore packets that aren't DNS Response
                pkt_req.append(packet)
                size_request.append(packet.length)
                size.append(float(packet.length))
                totalpacket += 1
                # print('request')
        # หาค่าเฉลี่ยของ size ทั้งหมด
        for i in range(len(size)):
            avg_size_total += float(size[i])
        if len(size) != 0:
            avg_size_total = avg_size_total/len(size)
        # หาค่าเฉลี่ยของ delay
        for i in range(len(delay)):
            avg_delay += float(delay[i])
        if len(delay) != 0:
            avg_delay = avg_delay/len(delay)
        # หาคู่
        for i in pkt_req:
            for j in pkt_resp:
                if i.dns.id == j.dns.id and len(pkt_resp) != old_resp:
                    matchcount += 1
                    old_resp = len(pkt_resp)
                    break
        num_lost = totalpacket-(matchcount*2)
        if totalpacket != 0:
            avg_lost = num_lost/totalpacket


def filter_icmp_file_packet(packet):
    global matchcount, size, delay, num_lost, avg_delay, avg_lost, avg_size_total, totalpacket, pkt_resp, pkt_req, old_resp
    url = 'https://notify-api.line.me/api/notify'
    token = '51P7BCktFo6YszYxIhQGFN1mKnGPLT6YYBNUtSJNTsC'
    headers = {'content-type': 'application/x-www-form-urlencoded',
               'Authorization': 'Bearer '+token}
    if hasattr(packet, 'icmp'):
        if packet.icmp.type == '0':  # type 0 = Echo reply
            totalpacket += 1
            pkt_resp.append(packet)
            size_response.append(packet.length)
            size.append(float(packet.length))
            delay.append(float(packet.icmp.resptime)/1000)
            print('response')
            if float(packet.icmp.resptime)/1000 >= 1:
                msg = 'Delay!!!!'
                r = requests.post(url, headers=headers,
                                  data={'message': msg})
                print(r.text)
                notification.notify(
                    title='Alert!!!',
                    message='High Delay',
                    app_icon="icon.ico",
                    timeout=5,
                )
                send_alert(receiver, "Delay is too high!")
        elif packet.icmp.type == '8':  # type 8 = Echo request
            totalpacket += 1
            pkt_req.append(packet)
            size_request.append(packet.length)
            size.append(float(packet.length))
            print('request')
        # หาค่าเฉลี่ยของ size ทั้งหมด
        for i in range(len(size)):
            avg_size_total += float(size[i])
        if len(size) != 0:
            avg_size_total = avg_size_total/len(size)
        # หาค่าเฉลี่ยของ delay
        for i in range(len(delay)):
            avg_delay += float(delay[i])
        if len(delay) != 0:
            avg_delay = avg_delay/len(delay)
        # หาคู่
        for i in pkt_req:
            for j in pkt_resp:
                if i.icmp.seq == j.icmp.seq and len(pkt_resp) != old_resp:
                    matchcount += 1
                    old_resp = len(pkt_resp)
                    break
        num_lost = totalpacket-(matchcount*2)
        if totalpacket != 0:
            avg_lost = num_lost/totalpacket


def filter_tcp_file_packet(packet):
    global matchcount, size, delay, num_lost, avg_delay, avg_lost, avg_size_total, totalpacket, pkt_resp, pkt_req, old_resp
    url = 'https://notify-api.line.me/api/notify'
    token = '51P7BCktFo6YszYxIhQGFN1mKnGPLT6YYBNUtSJNTsC'
    headers = {'content-type': 'application/x-www-form-urlencoded',
               'Authorization': 'Bearer '+token}
    if hasattr(packet, 'tcp'):
        try:
            if packet.tcp.analysis_ack_rtt:
                totalpacket += 1
                pkt_resp.append(packet)
                size_response.append(packet.length)
                size.append(float(packet.length))
                delay.append(float(packet.tcp.analysis_ack_rtt))
                # print('response')
                print(packet.tcp.analysis_ack_rtt)
                if float(packet.tcp.analysis_ack_rtt) >= 0.3:
                    msg = 'Delay!!!!'
                    r = requests.post(url, headers=headers,
                                      data={'message': msg})
                    print(r.text)
                    notification.notify(
                        title='Alert!!!',
                        message='High Delay',
                        app_icon="icon.ico",
                        timeout=5,
                    )
                    send_alert(receiver, "Delay is too high!")
        except AttributeError as e:
            # ถ้าไม่ใช่ Response
            totalpacket += 1
            pkt_req.append(packet)
            size_request.append(packet.length)
            size.append(float(packet.length))
            # print('request')
        # หาค่าเฉลี่ยของ size ทั้งหมด
        for i in range(len(size)):
            avg_size_total += float(size[i])
        if len(size) != 0:
            avg_size_total = avg_size_total/len(size)
        # หาค่าเฉลี่ยของ delay
        for i in range(len(delay)):
            avg_delay += float(delay[i])
        if len(delay) != 0:
            avg_delay = avg_delay/len(delay)
        # หาคู่
        for i in pkt_req:
            for j in pkt_resp:
                if (i.tcp.ack == j.tcp.nxtseq and i.tcp.dstport == j.tcp.srcport) and len(pkt_resp) != old_resp:
                    matchcount += 1
                    old_resp = len(pkt_resp)
                    break
        num_lost = totalpacket-(matchcount*2)
        if totalpacket != 0:
            avg_lost = num_lost/totalpacket


def result():
    global lasttime, starttime, lapnum, number_packet, delay, avg_size_total, avg_delay, num_lost, totalpacket, avg_lost, x
    avg_delay = round(avg_delay, 6)
    avg_lost = round(avg_lost, 6)
    avg_size_total = round(avg_size_total, 6)
    wb = Workbook()  # define excel
    # เพิ่ม sheet ใน excel/กำหนด sheet ที่จะทำการเพิ่มข้อมูล
    sheet1 = wb.add_sheet('Sheet 1')
    # sheet1.write(row,col, data, style)
    sheet1.write(0, 0, "Request Size")  # สร้าง column size
    sheet1.write(0, 1, "Respose Size")
    # ------------------------------------------------เผื่อแก้
    for i in range(len(size_request)):
        sheet1.write(i+1, 0, size_request[i])
    for i in range(len(size_response)):
        sheet1.write(i+1, 1, size_response[i])
    sheet1.write(0, 2, "Delay")  # สร้าง column delay
    for i in range(len(delay)):
        sheet1.write(i+1, 2, delay[i])
    sheet1.write(0, 4, "Max Size")  # เพิ่มค่าสูงสุดของ size
    sheet1.write(2, 4, "Min Size")  # เพิ่มค่าต่ำสุดของ size
    if len(size) != 0:
        sheet1.write(1, 4, max(size))
        sheet1.write(3, 4, min(size))
    else:
        sheet1.write(1, 4, '0')
        sheet1.write(3, 4, '0')
    sheet1.write(4, 4, "Total Lost")  # เพิ่ม lost packet ทั้งหมด
    sheet1.write(5, 4, num_lost)
    sheet1.write(6, 4, "Max Delay")  # เพิ่มค่าสูงสุดของ Delay
    sheet1.write(8, 4, "Min Delay")  # เพิ่มค่าต่ำสุดของ Delay
    if len(delay) != 0:
        sheet1.write(7, 4, max(delay))
        sheet1.write(9, 4, min(delay))
    sheet1.write(0, 5, "Avg. Size")  # เพิ่มค่าเฉลี่ยขนาดของ packet
    sheet1.write(1, 5, avg_size_total)
    sheet1.write(2, 5, "Avg. Lost")  # เพิ่มค่าเฉลี่ยของ lost packet
    sheet1.write(3, 5, avg_lost)
    sheet1.write(4, 5, "Avg. Delay")  # เพิ่มค่าเฉลี่ยของ delay
    sheet1.write(5, 5, avg_delay)

    for i in range(1, len(delay)+1):
        number_packet.append(i)

    sheet1.write(6, 5, "total packet")  # จำนวน http ทั้งหมด
    sheet1.write(7, 5, totalpacket)

    # สร้าง graph

    plt.rcParams["figure.figsize"] = [6.50, 2.50]
    plt.rcParams["figure.autolayout"] = True

    x = number_packet
    y = delay
    plt.title("Delay of tranfer packet")
    plt.xlabel("Packet Order")
    plt.ylabel("Delay(s)")
    plt.plot(x, y)
    plt.savefig("image.jpg")
    plt.show(block=False)
    plt.close()

    # เพิ่มรูปใน excel
    file_in = "image.jpg"
    img = Image.open(file_in)
    file_out = 'test1.bmp'
    if len(img.split()) == 4:
        # prevent IOError: cannot write mode RGBA as BMP
        r, g, b, a = img.split()
        img = Image.merge("RGB", (r, g, b))
        img.save(file_out)
    else:
        img.save(file_out)

    sheet1.insert_bitmap(file_out, 0, 8)

    # The current lap-time
    laptime = round((time.time() - lasttime), 2)

    # Updating the previous total time and lap number
    lasttime = time.time()
    lapnum += 1

    sheet1.write(8, 5, "Timer")  # เวลารันของรอบนั้นๆ
    sheet1.write(9, 5, laptime)

    # PDF
    count = 32
    timer = datetime.datetime.now()
    now = str(timer.day) + '/' + str(timer.month) + '/' + str(timer.year)
    msg = ['Max Size', 'Min Size', 'Max Delay', 'Min Delay', 'Avg Size',
           'Avg Delay', 'Total Lost', 'Avg Lost', 'Total Packet', 'Timer']
    value = []
    size_count = []
    size_count.append(len(size_request))
    size_count.append(len(size_response))
    if len(size) != 0:
        value.append(max(size))
        value.append(min(size))
        value.append(max(delay))
        value.append(min(delay))
        value.append(float(avg_size_total))
        value.append(float(avg_delay))
        value.append(num_lost)
        value.append(float(avg_lost))
        value.append(totalpacket)
        value.append(laptime)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 24)
    pdf.cell(w=0, h=20, txt="Summary Report", ln=1)

    pdf.set_font('Arial', '', 16)
    pdf.cell(w=30, h=8, txt="Date : ", ln=0)
    pdf.cell(w=30, h=8, txt=now, ln=1)

    pdf.image('./image.jpg',
              x=10, y=None, w=190, h=0, type='JPG')

    pdf.set_font('Arial', 'B', 16)
    pdf.cell(w=30, h=8, txt="Req. Size", border=1, ln=0)
    pdf.cell(w=30, h=8, txt="Res. Size", border=1, ln=1)
    pdf.set_font('Arial', '', 16)
    if max(size_count) < 10 and len(size) != 0:
        for i in range(max(size_count)):
            if i < min(size_count):
                pdf.cell(w=30, h=8, txt=size_request[i], border=1, ln=0)
                pdf.cell(w=30, h=8, txt=size_response[i], border=1, ln=0)
            elif i >= min(size_count) and len(size_request) < len(size_response):
                pdf.cell(w=30, h=8, txt=size_response[i], border=1, ln=0)
                pdf.cell(w=30, h=8, txt="", border=0, ln=0)
            elif i >= min(size_count) and len(size_request) > len(size_response):
                pdf.cell(w=30, h=8, txt=size_request[i], border=1, ln=0)
                pdf.cell(w=30, h=8, txt="", border=0, ln=0)
            pdf.cell(w=30, h=8, txt="", border=0, ln=0)
            pdf.cell(w=45, h=8, txt=msg[i], border=1, ln=0, align='C')
            pdf.cell(w=45, h=8, txt=str(value[i]), border=1, ln=1, align='C')
        for i in range(max(size_count), 10):
            pdf.cell(w=30, h=8, txt="", border=0, ln=0)
            pdf.cell(w=30, h=8, txt="", border=0, ln=0)
            pdf.cell(w=30, h=8, txt="", border=0, ln=0)
            pdf.cell(w=45, h=8, txt=msg[i], border=1, ln=0, align='C')
            pdf.cell(w=45, h=8, txt=str(value[i]), border=1, ln=1, align='C')
    elif max(size_count) > 9 and len(size) != 0:
        for i in range(max(size_count)):
            if i < 19:
                if i < 10:
                    pdf.cell(w=30, h=8, txt=size_request[i], border=1, ln=0)
                    pdf.cell(w=30, h=8, txt=size_response[i], border=1, ln=0)
                    pdf.cell(w=30, h=8, txt="", border=0, ln=0)
                    pdf.cell(w=45, h=8, txt=msg[i], border=1, ln=0, align='C')
                    pdf.cell(w=45, h=8, txt=str(
                        value[i]), border=1, ln=1, align='C')
                else:
                    if i < min(size_count):
                        pdf.cell(
                            w=30, h=8, txt=size_request[i], border=1, ln=0)
                        pdf.cell(
                            w=30, h=8, txt=size_response[i], border=1, ln=1)
                    elif i >= min(size_count) and len(size_request) < len(size_response):
                        pdf.cell(w=30, h=8, txt="-", border=1, ln=0)
                        pdf.cell(
                            w=30, h=8, txt=size_response[i], border=1, ln=1)
                    elif i >= min(size_count) and len(size_request) > len(size_response):
                        pdf.cell(
                            w=30, h=8, txt=size_request[i], border=1, ln=0)
                        pdf.cell(w=30, h=8, txt="-", border=1, ln=1)
            else:
                if count == 32:
                    count = 0
                    pdf.set_font('Arial', 'B', 16)
                    pdf.cell(w=30, h=8, txt="Req. Size", border=1, ln=0)
                    pdf.cell(w=30, h=8, txt="Res. Size", border=1, ln=1)
                    pdf.set_font('Arial', '', 16)
                if i < min(size_count):
                    pdf.cell(w=30, h=8, txt=size_request[i], border=1, ln=0)
                    pdf.cell(w=30, h=8, txt=size_response[i], border=1, ln=1)
                elif i >= min(size_count) and len(size_request) < len(size_response):
                    pdf.cell(w=30, h=8, txt="-", border=1, ln=0)
                    pdf.cell(w=30, h=8, txt=size_response[i], border=1, ln=1)
                elif i >= min(size_count) and len(size_request) > len(size_response):
                    pdf.cell(w=30, h=8, txt=size_request[i], border=1, ln=0)
                    pdf.cell(w=30, h=8, txt="-", border=1, ln=1)
                count += 1

    # เขียนไฟล์ Excel & PDF
    x = datetime.datetime.now()
    dattime = x.strftime("%a-%d%m%y-%H%M%S")
    snameex = "excel/" + dattime + "-result.xls"
    snamepdf = 'pdf/' + dattime + '.pdf'
    wb.save("excel/" + dattime + "-result.xls")
    pdf.output(f'pdf/' + dattime + '.pdf', 'F')
    send_report(receiver, "Report for today", [snameex, snamepdf])
    print(delay)
    reset_value()
    print('finist')

def send_alert(send_to, text):
    assert isinstance(send_to, list)
    port = 465  # For SSL
    smtp_server = "smtp.gmail.com"
    sender_email = "62070147@it.kmitl.ac.th"  # Enter your address
    receiver_email = send_to  # Enter receiver address
    password = "GXVuym23"

    msg = MIMEMultipart()
    msg['From'] = '62070147@it.kmitl.ac.th'
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = "Alert!! Network Problem"

    msg.attach(MIMEText(text))
    
    context = ssl.create_default_context()
    
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, msg.as_string())

def send_report(send_to, text, files=None):
    # assert isinstance(send_to, list)
    port = 465  # For SSL
    smtp_server = "smtp.gmail.com"
    sender_email = "62070147@it.kmitl.ac.th"  # Enter your address
    receiver_email = send_to  # Enter receiver address
    password = "GXVuym23"

    msg = MIMEMultipart()
    msg['From'] = '62070147@it.kmitl.ac.th'
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = "Report"

    msg.attach(MIMEText(text))

    for f in files or []:
        with open(f, "rb") as fil:
            part = MIMEApplication(
                fil.read(),
                Name=basename(f)
            )
        # After the file is closed
        part['Content-Disposition'] = 'attachment; filename="%s"' % basename(f)
        msg.attach(part)
    
    context = ssl.create_default_context()
    
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, msg.as_string())

def reset_value():
    global lasttime, starttime, lapnum, number_packet, delay, avg_size_total, avg_delay, num_lost, totalpacket, old_ack, avg_lost, matchcount, old_resp
    matchcount = 0
    nxtseq.clear()
    ack.clear()
    size.clear()
    request_uri.clear()
    response_uri.clear()
    size_request.clear()
    size_response.clear()
    avg_size_total = 0
    delay.clear()
    avg_delay = 0.0
    num_lost = 0
    number_packet.clear()
    totalpacket = 0
    starttime = time.time()
    lasttime = starttime
    old_ack = 0
    avg_lost = 0
    pkt_resp.clear()
    pkt_req.clear()
    old_resp = 0


def main():
    global receiver
    #Read config.ini file
    config_obj = configparser.ConfigParser()
    config_obj.read("./configfile.ini")
    usersetting = config_obj["usersetting"]
    # set your parameters for the database connection URI using the keys from the configfile.ini
    run_type = usersetting["runtype"]
    pcap_file = usersetting["pcapfile"]
    network_interface = usersetting["networkinterface"]
    parse_type = usersetting["parsetype"]
    get_receiver = config_obj.get("usersetting", "receiver")
    receiver = json.loads(get_receiver)
    if run_type == "live":
        capture_live_packets(parse_type, network_interface)
    elif run_type == "file":
        capture_file_packets(parse_type, pcap_file)
    else:
        print("Error!! Can run on file or live packet")

if __name__ == "__main__":
    main()
