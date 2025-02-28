# Prisma SD-WAN O365 Global Prefix Sync (Preview)
The purpose of this script is to download a list of IPv4 prefixes from O365 endpoint list and populate them as a Path/Security/QoS Global Prefix. 

#### License
MIT

#### Requirements
* Active Prisma Account - Please generate your service account prismasase_settings.py
* Python >=3.7

#### Installation:
 Scripts directory. 
 - **Github:** Download files to a local directory, manually run the scripts. 
 - pip install -r requirements.txt

### Examples of usage:
 Please generate your API token and add it to cloudgenix_settings.py
 
 1. ./o365-prefix.py 
      - This will check the O365 endpoint list every 5 minutes and make sure the path global prefix O365-Prefix is up to date.
### Caveats and known issues:
 - This is a PREVIEW release, hiccups to be expected. Please file issues on Github for any problems.

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional Prisma SD-WAN Documentation at <https://docs.paloaltonetworks.com/prisma/cloudgenix-sd-wan.html>
