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
from email.utils import COMMASPACE

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

totalpacket = 0
num_req = 0
num_res = 0
num_round_t = []
num_round_req = []
num_round_res = []
timer_match = []
number_packet_t = []
number_packet_req = []
number_packet_res = []

def capture_live_packets():
    # cap = pyshark.LiveCapture("Wi-Fi 2")
    schedule.every(1).second.do(counter)
    schedule.every(1).minutes.do(result)
    # for packet in cap.sniff_continuously():
    #     schedule.run_pending()
    #     filter_tcp_live_packet(packet)
    capture = pyshark.FileCapture('pcap/test.pcapng')
    for packet in capture:
        schedule.run_pending()
        filter_tcp_live_packet(packet)

def filter_tcp_live_packet(packet):
    global matchcount, size, delay, num_lost, avg_delay, avg_lost, avg_size_total, totalpacket, pkt_resp, pkt_req, old_resp, num_req, num_res
    url = 'https://notify-api.line.me/api/notify'
    token = '51P7BCktFo6YszYxIhQGFN1mKnGPLT6YYBNUtSJNTsC'
    headers = {'content-type': 'application/x-www-form-urlencoded',
               'Authorization': 'Bearer '+token}
    if hasattr(packet, 'tcp'):
        try:
            if packet.tcp.analysis_ack_rtt:
                totalpacket += 1
                num_res += 1
                pkt_resp.append(packet)
                size_response.append(packet.length)
                size.append(float(packet.length))
                delay.append(float(packet.tcp.analysis_ack_rtt))
        except AttributeError as e:
            # ถ้าไม่ใช่ Response
            totalpacket += 1
            num_req += 1
            pkt_req.append(packet)
            size_request.append(packet.length)
            size.append(float(packet.length))

def counter():
    global totalpacket, num_req, num_res, num_round_t, num_round_req, num_round_res
    num_round_t.append(totalpacket)
    num_round_req.append(num_req)
    num_round_res.append(num_res)
    print(totalpacket)
    totalpacket = 0
    num_req = 0
    num_res = 0

def result():
    global number_packet_t, number_packet_req, number_packet_res
    for i in range(1, len(num_round_t)+1):
        number_packet_t.append(i)
    for i in range(1, len(num_round_req)+1):
        number_packet_req.append(i)
    for i in range(1, len(num_round_res)+1):
        number_packet_res.append(i)

# สร้าง graph
    plt.rcParams["figure.figsize"] = [6.50, 2.50]
    plt.rcParams["figure.autolayout"] = True

    x = num_round_t
    y = number_packet_t
    plt.title("total packet every second")
    plt.xlabel("time(second)")
    plt.ylabel("number packet")
    plt.plot(x, y)
    plt.savefig("image_t.jpg")
    plt.show(block=False)
    plt.close()

    plt.rcParams["figure.figsize"] = [6.50, 2.50]
    plt.rcParams["figure.autolayout"] = True

    x = number_packet_req
    y = num_round_req
    plt.title("request packet every second")
    plt.xlabel("time(second)")
    plt.ylabel("number packet")
    plt.plot(x, y)
    plt.savefig("image_req.jpg")
    plt.show(block=False)
    plt.close()

    plt.rcParams["figure.figsize"] = [6.50, 2.50]
    plt.rcParams["figure.autolayout"] = True

    x = number_packet_res
    y = num_round_res
    plt.title("response packet every second")
    plt.xlabel("time(second)")
    plt.ylabel("number packet")
    plt.plot(x, y)
    plt.savefig("image_res.jpg")
    plt.show(block=False)
    plt.close()

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 24)
    pdf.cell(w=0, h=20, txt="Summary Report", ln=1)

    pdf.image('./image_t.jpg',
              x=10, y=None, w=190, h=0, type='JPG')
    pdf.image('./image_req.jpg',
              x=10, y=None, w=190, h=0, type='JPG')
    pdf.image('./image_res.jpg',
              x=10, y=None, w=190, h=0, type='JPG')
    
    x = datetime.datetime.now()
    dattime = x.strftime("%a-%d%m%y-%H%M%S")
    pdf.output(f'pdf/test'+ dattime +'.pdf', 'F')
    print('finish')

    
capture_live_packets()