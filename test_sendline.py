#!/usr/local/bin/python3
import requests
url = 'https://notify-api.line.me/api/notify'
token = '51P7BCktFo6YszYxIhQGFN1mKnGPLT6YYBNUtSJNTsC'
headers = {'content-type':'application/x-www-form-urlencoded','Authorization':'Bearer '+token}

msg = 'Delay!!!!'
r = requests.post(url, headers=headers, data = {'message':msg})
print (r.text)