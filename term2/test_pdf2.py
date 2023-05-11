from fpdf import FPDF
import datetime

time = datetime.datetime.now()
now = str(time.day) + '/' + str(time.month) + '/' + str(time.year)
msg = ['Max Size', 'Min Size', 'Max Delay', 'Min Delay', 'Avg Size',
       'Avg Delay', 'Total Lost', 'Avg Lost', 'Total Packet', 'Timer']

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
# pdf.cell(w=30, h=8, txt="", border=0, ln=0)
pdf.set_font('Arial', '', 16)
# pdf.cell(w=45, h=8, txt='Max Size', border=1, ln=0, align='C')
# pdf.cell(w=45, h=8, txt='Feature 2', border=1, ln=1, align='C')
count = 32
for i in range(200):
    if i < 19:
        if i < 10:
            pdf.cell(w=30, h=8, txt="i", border=1, ln=0)
            pdf.cell(w=30, h=8, txt=str(i), border=1, ln=0)
            pdf.cell(w=30, h=8, txt="", border=0, ln=0)
            pdf.cell(w=45, h=8, txt=msg[i], border=1, ln=0, align='C')
            pdf.cell(w=45, h=8, txt='Feature 2', border=1, ln=1, align='C')
        else:
            pdf.cell(w=30, h=8, txt="i", border=1, ln=0)
            pdf.cell(w=30, h=8, txt=str(i), border=1, ln=1)
    else:
        if count == 32:
            count = 0
            pdf.set_font('Arial', 'B', 16)
            pdf.cell(w=30, h=8, txt="Req. Size", border=1, ln=0)
            pdf.cell(w=30, h=8, txt="Res. Size", border=1, ln=1)
            pdf.set_font('Arial', '', 16)
        pdf.cell(w=30, h=8, txt="i", border=1, ln=0)
        pdf.cell(w=30, h=8, txt=str(i), border=1, ln=1)
        count += 1
        print(count)

# pdf.add_page()
# for i in range(35):
#     pdf.cell(w=30, h=8, txt="i", border=1, ln=0)
#     pdf.cell(w=30, h=8, txt=str(i), border=1, ln=1)

pdf.output(f'./example.pdf', 'F')
