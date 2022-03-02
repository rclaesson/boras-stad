#!/usr/bin/python3

# Modules
import requests, smtplib, argparse, urllib3, datetime, re, json
from email.message import EmailMessage
from zeep import Client
from zeep.transports import Transport
from requests import Session
from requests.auth import HTTPBasicAuth
urllib3.disable_warnings()

# Logging
logfile = open("/opt/plugins/custom/notify-visionflow/op5-visionflow.log", "a")

# Arguments
parser = argparse.ArgumentParser(description="Create VisionFlow tickets from OP5 notifications.")
parser.add_argument("-oh", "--op5host", help="OP5 Monitor IP/FQDN", type=str, required=True)
parser.add_argument("-ou", "--op5user", help="OP5 Monitor API User", type=str, required=True)
parser.add_argument("-op", "--op5pass", help="OP5 Monitor API Password", type=str, required=True)
parser.add_argument("-vh", "--vflowhost", help="VisionFlow IP/FQDN", type=str, required=True)
parser.add_argument("-vu", "--vflowuser", help="VisionFlow API User", type=str, required=True)
parser.add_argument("-vp", "--vflowpass", help="VisionFlow API Password", type=str, required=True)
parser.add_argument("-d", "--duration", help="Time service must have been in alerting state (Default = 30min).", type=int, required=False, default=30)
args = parser.parse_args()

# Timestamps
current_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
duration_time_ago = datetime.datetime.now() - datetime.timedelta(minutes=args.duration)

# Hostgroups used in OP5
f = open("/opt/plugins/custom/notify-visionflow/hostgroups_alert.lst", "r")
hostgroups_alert = f.readlines()
f.close()
# Business Services used in OP5
f = open("/opt/plugins/custom/notify-visionflow/bs_hosts.lst", "r")
bs_hosts = f.readlines()
f.close()

# OP5 API queries
def op5_api_query(filter_url):
  try:
    query = requests.get("https://" + args.op5host + "/api/filter/query?query=" + filter_url, auth=(args.op5user, args.op5pass), verify=False)
  except requests.exceptions.RequestException as error:
    print (str(current_timestamp) + " [localhost] HTTP: " + str(error), file = logfile)
    raise SystemExit(error)
  return query

# Check ticket existence
def check_ticket(hostname, service, state):
  wsdl = "http://" + args.vflowhost + "/api/docs/service.wsdl?class=vf?namespace=ws"
  proxy_url = "http://" + args.vflowhost + "/service/VisionProject-v2/VisionProjectWebServiceService"

  try:
    session = Session()
    client = Client(wsdl,transport=Transport(session=session))
    client.service._binding_options["address"] = proxy_url
    loginResult = client.service.login2(username=args.vflowuser, password=args.vflowpass, visionProjectVersion="13.0")
    result = client.service.getQueryResult("822")
  except requests.exceptions.RequestException as error:
    print (str(current_timestamp) + " [localhost] HTTP: " + str(error), file = logfile)
    raise SystemExit(error)

  # Check if tickets exists
  if result:
    op5_host_and_service = "[OP5] " + service + " on " + hostname + " is " + state
    global ticket_creation
    ticket_host_and_service = []

    for ticket in result:
      ticket_host_and_service.append(ticket["name"])

    if op5_host_and_service in ticket_host_and_service:
      print (current_timestamp + " [localhost] TICKET INFO: Ticket already exists for " + service + " on host " + hostname + ". Will not create new ticket.", file = logfile)
      ticket_creation = 0
    else:
      ticket_creation = 1
        
    return ticket_creation

  # If no tickets were found, create new ticket
  else:
    ticket_creation = 1
    return ticket_creation

# Create ticket
def create_ticket(hostname, service, alert_timestamp, plugin_output, ack_msg, contact_email, state):
  ticket_subject = "[OP5] " + service + " on " + hostname + " is " + state
  ticket_message = "ITRS OP5 Monitor \n\n" \
  "Service: " + service + " on host " + hostname + " has passed the " + state + " threshold. \n\n" \
  "Output: " + plugin_output + "\n" \
  "Alert detected at: " + str(alert_timestamp) + "\n\n" \
  "Acknowledgement: " + ack_msg
  msg = EmailMessage()
  msg.set_content(ticket_message)
  msg['Subject'] = ticket_subject
  msg['From'] = "op5Monitor@viop5.ad.boras.se"
  msg['To'] = contact_email
  # Send the message
  s = smtplib.SMTP('localhost')
  s.send_message(msg)
  s.quit()

# Get alerts from OP5 Monitor Business Services
req_business_alert_list = []
for bs_alert in bs_hosts:
  req_business_alert = op5_api_query("[services] host.name = " + bs_alert + " and state = 2 and state_type = 1 and scheduled_downtime_depth = 0 and host.scheduled_downtime_depth = 0&columns=host.name,description,last_time_ok,plugin_output,acknowledged,comments_with_info,contacts,state")
  req_business_alert = req_business_alert.json()
  if req_business_alert:
    req_business_alert_list.append(req_business_alert)

# Get alerts from OP5 Monitor Hostgroups
req_infra_alert_list = []
for hg_alert in hostgroups_alert:
  req_infra_alert = op5_api_query("[services] host in " + hg_alert + " and (state = 1 or state = 2) and state_type = 1 and scheduled_downtime_depth = 0 and host.scheduled_downtime_depth = 0&columns=host.name,description,last_time_ok,plugin_output,acknowledged,comments_with_info,contacts,state")
  req_infra_alert = req_infra_alert.json()
  if req_infra_alert:
    req_infra_alert_list.append(req_infra_alert)

# Business services alerts
if req_business_alert_list:
  if not req_infra_alert_list:
    for item in req_business_alert_list[0]:
      hostname = str(item["host"]["name"])
      service = str(item["description"])
      last_time_ok = item["last_time_ok"]
      plugin_output = str(item["plugin_output"])
      state = item["state"]
      if state == 1:
        state = "WARNING"
      elif state == 2:
        state = "CRITICAL"

      # Convert timestamp to readable format
      alert_timestamp = datetime.datetime.fromtimestamp(last_time_ok)

      # Check acknowledgement
      if str(item["acknowledged"]) == "1":
        ack_user = str(item["comments_with_info"][-1][1])
        ack_comment = str(item["comments_with_info"][-1][2])
        ack_msg = ack_comment + ". From user: " + ack_user
      else:
        ack_msg = "Service is not acknowledged."

      # Get contact email
      for contact in item["contacts"]:
        contact_email = op5_api_query("[contacts] name = " + '"' + contact + '"' + "&columns=address1")
        contact_email = contact_email.json()
        contact_email = contact_email[0]["address1"]
        if contact_email:
          contact_email_address = contact_email

      # Check duration
      if alert_timestamp < duration_time_ago:
        # Check contact existence
        if contact_email_address:
          # Check ticket existence
          check_ticket(hostname, service, state)
          if ticket_creation == 1:
            # Create ticket
            create_ticket(hostname, service, alert_timestamp, plugin_output, ack_msg, contact_email_address, state)
            print (current_timestamp + " [localhost] TICKET CREATED: Service " + service + " on host " + hostname, file = logfile)
        else:
          print (current_timestamp + " [localhost] BUSINESS SERVICES: Could not find email address for contact " + contact + ". Will not create ticket.", file = logfile)
      else:
        print (current_timestamp + " [localhost] BUSINESS SERVICES: Service " + service + " on host " + hostname + " has not passed the duration threshold. Will not create ticket.", file = logfile)
  else:
    print (current_timestamp + " [localhost] BUSINESS SERVICES: Issues found with parent objects. Will not create ticket(s).", file = logfile)
else:
  print (current_timestamp + " [localhost] BUSINESS SERVICES: No issues was found.", file = logfile)

# Infrastructure alerts
if req_infra_alert_list:
  # Sort items
  for item in req_infra_alert_list[0]:
    hostname = str(item["host"]["name"])
    service = str(item["description"])
    last_time_ok = item["last_time_ok"]
    plugin_output = str(item["plugin_output"])
    state = item["state"]
    if state == 1:
      state = "WARNING"
    elif state == 2:
      state = "CRITICAL"

    # Convert timestamp to datetime-object
    alert_timestamp = datetime.datetime.fromtimestamp(last_time_ok)

    # Check acknowledgement
    if str(item["acknowledged"]) == "1":
      ack_user = str(item["comments_with_info"][-1][1])
      ack_comment = str(item["comments_with_info"][-1][2])
      ack_msg = ack_comment + ". From user: " + ack_user
    else:
      ack_msg = "Service is not acknowledged."

    # Get contact email
    for contact in item["contacts"]:
      contact_email = op5_api_query("[contacts] name = " + '"' + contact + '"' + "&columns=address1")
      contact_email = contact_email.json()
      contact_email = contact_email[0]["address1"]
      if contact_email:
        contact_email_address = contact_email

    # Check if host-object is not down
    host_is_down = op5_api_query("[hosts] name = " + hostname + " and state = 1")
    if host_is_down:
      print (current_timestamp + " [localhost] INFRASTRUCTURE: Host-object " + hostname + " is down. Will not create tickets for service-objects.", file = logfile)
    else:
      # Check duration
      if alert_timestamp < duration_time_ago:
        # Check contact existence
        if contact_email_address:
          # Check ticket existence
          check_ticket(hostname, service, state)
          if ticket_creation == 1:
            # Create ticket
            create_ticket(hostname, service, alert_timestamp, plugin_output, ack_msg, contact_email_address, state)
            print (current_timestamp + " [localhost] TICKET CREATED: Service " + service + " on host " + hostname, file = logfile)
        else:
          print (current_timestamp + " [localhost] INFRASTRUCTURE: Could not find email address for contact " + contact + ". Will not create ticket(s).", file = logfile)
      else:
         print (current_timestamp + " [localhost] INFRASTRUCTURE: Service " + service + " on host " + hostname + " has not passed the duration threshold. Will not create ticket.", file = logfile)
else:
  print (current_timestamp + " [localhost] INFRASTRUCTURE: No issues was found.", file = logfile)

# Done
