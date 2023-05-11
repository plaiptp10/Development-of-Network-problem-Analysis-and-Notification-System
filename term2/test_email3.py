import smtplib
import ssl
from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate

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
    msg['Subject'] = "Alert!! Delay is too high"

    msg.attach(MIMEText(text))
    
    context = ssl.create_default_context()
    
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, msg.as_string())

send_alert(["62070147@it.kmitl.ac.th"], "Alert!! delay")