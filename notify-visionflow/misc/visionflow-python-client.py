#!/usr/bin/python3

import json, re
from zeep import Client
from zeep.transports import Transport
from requests import Session
from requests.auth import HTTPBasicAuth
url = "http://10.106.248.154:8080"
wsdl = url + "/api/docs/service.wsdl?class=vf?namespace=ws"
proxy_url = url + "/service/VisionProject-v2/VisionProjectWebServiceService"

session = Session()
client = Client(wsdl,transport=Transport(session=session))

client.service._binding_options["address"] = proxy_url
loginResult = client.service.login2(username="Adminsson", password="otto1988", visionProjectVersion="13.0")

result = client.service.getQueryResult("822")
if result:
  ticket_host_and_service_raw = (ticket["name"])
  print (ticket_host_and_service_raw)
else:
  print ("No tickets were found.")
  exit(0)

for ticket in result:
  ticket_host_and_service_raw = (ticket["name"])
  try:
    ticket_host_and_service = re.findall(r'\'(.*?)\'', ticket_host_and_service_raw)
    ticket_host_name = str(ticket_host_and_service[1])
    ticket_service_name = str(ticket_host_and_service[0])
    ticket_host_and_service = ticket_host_name + ";" + ticket_service_name
    print (ticket_host_and_service)
  except:
    print ("Could not match '" + str(ticket_host_and_service_raw) + "' with object in OP5 Monitor. Will not create ticket.")
