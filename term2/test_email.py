from email.message import EmailMessage
import ssl
import smtplib

files = ["example.pdf", "pdf/pdf0.pdf"]

def send_email(msg):
    port = 465  # For SSL
    smtp_server = "smtp.gmail.com"
    sender_email = "62070147@it.kmitl.ac.th"  # Enter your address
    receiver_email = "62070147@it.kmitl.ac.th"  # Enter receiver address
    password = "GXVuym23"

    subject = 'Alert'
    body = msg

    em = EmailMessage()
    em['From'] = sender_email
    em['To'] = receiver_email
    em['Subject'] = subject
    em.set_content(body)
        
    with open("example.pdf", 'rb') as attach:
        file_data = attach.name
        file_name = attach.name
    
    em.add_attachment(file_data, subtype = "octret-stream", filename = file_name)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, em.as_string())

send_email('report')