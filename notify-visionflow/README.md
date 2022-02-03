# Notify VisionFlow

## Notify VisionFlow is a software used to create tickets in VisionFlow from OP5 alerts.

### Requirements
* python3.6 (higher could work)
* python-requests
* python-zeep
* OP5 API credentials
* VisionFlow API credentials

### Instructions
_notify-visionflow.py_ reads two files to sort out which host groups and BSM-hosts contains the infrastructure:
* _bs_hosts.lst_
* _hostgroups_alert.lst_

By reading these files, Notify VisionFlow can build a network topology and use the topology to mitigate alarm storms. <br />
For example if the DNS-service become unavailable, we don't want to create hundreds of tickets because servers can't communicate. One ticket is enough.

### Contacts
VisionFlow creates tickets from incoming e-mails. <br />
Notify VisionFlow reads the email-address from contacts in OP5 in order to find the right e-mail address, so the ticket is being created in the correct folder. <br />

Apply the VisionFlow e-mail address to the field **address1** in OP5, and omit the **email** field. <br />
Using the **email** field initializes standard OP5 notifications, which will cause duplicate tickets in VisionFlow.

### Example usage
    ./notify-visionflow.py -oh <op5host> -ou <op5user> -op <op5pass> -vh <vflowhost> -vu <vflowuser> -vp <vflowpass> -d <duration, in minutes>
