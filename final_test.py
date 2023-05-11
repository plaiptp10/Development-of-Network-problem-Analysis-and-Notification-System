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

while 1:

    folder = "pcap"
    dl = os.listdir(folder)

    for file in dl:
        # capture packet from file filter response http
        cap_request = pyshark.FileCapture(
            "pcap/"+file, display_filter='http.request.method == "GET"')
        cap_response = pyshark.FileCapture(
            "pcap/"+file, display_filter='http.response.code!=0')
        # define value
        matchcount = 0
        nxtseq = []
        ack = []
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
        for packet in cap_request:
            nxtseq.append(packet.tcp.nxtseq)
            request_uri.append(packet.http.request_full_uri)
        for packet in cap_response:
            try:
                respose_uri.append(packet.http.response_for_uri)
                ack.append(packet.tcp.ack)
            except AttributeError:
                num_lost += 1
        # หาขนาดของ request packet
        for packet in cap_request:
            size.append(float(packet.length))
            size_request.append(packet.length)
        # หาค่า delay ของ packet และแจ้งเตือนผ่านไลน์และหนัาจอคอม หาขนาดของ respose packet
        for packet in cap_response:
            try:
                delay.append(float(packet.http.time))
            except:
                continue
            size.append(float(packet.length))
            size_respose.append(packet.length)
            if float(packet.http.time) >= 0.3:
                msg = 'Delay!!!!'
                r = requests.post(url, headers=headers, data={'message': msg})
                print(r.text)
                notification.notify(
                    title='Alert!!!',
                    message='High Delay',
                    app_icon="icon.ico",
                    timeout=5,
                )
        if len(size) == 0:
            try:
                os.remove("pcap/"+file)
                break
            except PermissionError:
                break

        # หาค่าเฉลี่ยของ size ทั้งหมด
        for i in range(len(size)):
            avg_size_total += float(size[i])
        avg_size_total = avg_size_total/len(size)
        totalpacket = (sum(1 for _ in cap_request) +
                       sum(1 for _ in cap_response))

        # หาค่าเฉลี่ยของ delay
        for i in range(len(delay)):
            avg_delay += float(delay[i])
        if len(delay) != 0:
            avg_delay = avg_delay/len(delay)
        else:
            try:
                os.remove("pcap/"+file)
                break
            except PermissionError:
                break

        # หาจำนวนที่ match และ lost
        for i in range(0, len(nxtseq)):
            check_lost = 0
            for j in range(0, len(ack)):
                if nxtseq[i] == ack[j] and request_uri[i] == respose_uri[j]:
                    matchcount += 1
                    check_lost += 1
                    break
            if check_lost == 0:
                num_lost += 1
        # หาค่า Avg. lost
        avg_lost = num_lost/(sum(1 for _ in cap_request) +
                             sum(1 for _ in cap_response))
        wb = Workbook()  # define excel
        # เพิ่ม sheet ใน excel/กำหนด sheet ที่จะทำการเพิ่มข้อมูล
        sheet1 = wb.add_sheet('Sheet 1')
        # sheet1.write(row,col, data, style)
        sheet1.write(0, 0, "Request Size")  # สร้าง column size
        sheet1.write(0, 1, "Respose Size")
        for i in range(len(size_request)):
            sheet1.write(i+1, 0, size_request[i])
        for i in range(len(size_respose)):
            sheet1.write(i+1, 1, size_respose[i])
        sheet1.write(0, 2, "Delay")  # สร้าง column delay
        for i in range(len(delay)):
            sheet1.write(i+1, 2, delay[i])
        sheet1.write(0, 4, "Max Size")  # เพิ่มค่าสูงสุดของ size
        sheet1.write(1, 4, max(size))
        sheet1.write(2, 4, "Min Size")  # เพิ่มค่าต่ำสุดของ size
        sheet1.write(3, 4, min(size))
        sheet1.write(4, 4, "Total Lost")  # เพิ่ม lost packet ทั้งหมด
        sheet1.write(5, 4, num_lost)
        sheet1.write(6, 4, "Max Delay")  # เพิ่มค่าสูงสุดของ Delay
        sheet1.write(7, 4, max(delay))
        sheet1.write(8, 4, "Min Delay")  # เพิ่มค่าต่ำสุดของ Delay
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

        plt.rcParams["figure.figsize"] = [7.50, 3.50]
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

        # Total time elapsed since the timer started
        totaltime = round((time.time() - starttime), 2)

        # Updating the previous total time and lap number
        lasttime = time.time()
        lapnum += 1

        sheet1.write(8, 5, "Timer")  # เวลารันของรอบนั้นๆ
        sheet1.write(9, 5, laptime)

        # เขียนไฟล์ Excel
        wb.save("excel/" + file + ".xls")

        try:
            os.remove("pcap/"+file)
        except PermissionError:
            break

    if len(dl) == 0:
        break
