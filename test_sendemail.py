import smtplib

# creates SMTP session
s = smtplib.SMTP('smtp.gmail.com', 587)

# start TLS for security
s.starttls()

# Authentication
s.login("plaimage1202@gmail.com", "plaiplaiza342")

# message to be sent
message = "Message_you_need_to_send"

# sending the mail
s.sendmail("plaiie12@gmail.com", "suchanya.sompa2544@gmail.com", message)

# terminating the session
s.quit()
