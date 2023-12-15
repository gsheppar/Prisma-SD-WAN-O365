#!/usr/bin/env python3
import cloudgenix
import argparse
from cloudgenix import jd, jd_detailed, jdout
import cloudgenix_settings
import sys
import logging
import ipaddress
import os
import datetime
from datetime import datetime, timedelta
import sys
import csv
from csv import DictReader
import subprocess
import requests
import json
import schedule
import time



# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Example syslog script'
SCRIPT_VERSION = "v1"

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

def o365(cgx):
    
    url = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"
    response = requests.get(url)
    
    ipv4_addresses = []
    # Check if the request was successful
    if response.status_code == 200:
        data = response.json()
        
        for item in data:
            if "ips" in item:
                print("Checking "  + item["serviceAreaDisplayName"])
                for ip in item["ips"]:
                    try:
                        ipaddress.IPv4Network(ip)
                        if ip not in ipv4_addresses:
                            ipv4_addresses.append(ip)
                    except ipaddress.AddressValueError:
                        try:
                            ipaddress.IPv6Network(ip)
                        except ipaddress.AddressValueError:
                            print("Invalid IPv4 address: " + ip)
                        
    
    else:
        print("Failed to retrieve data. Status code:", response.status_code)
    
    prefix_name = "O365-Prefix"
    
    prefix_found = False
    prefix_data = None
    for item in cgx.get.networkpolicyglobalprefixes().cgx_content['items']:
        if item["name"] == prefix_name:
            prefix_found = True
            prefix_data = item
            
    
    if not prefix_found:
        data = {"name":prefix_name,"tags":[],"ipv4_prefixes":ipv4_addresses,"ipv6_prefixes":[],"description":None}
        
        resp = cgx.post.networkpolicyglobalprefixes(data=data)
        if not resp:
            print("ERROR creating prefix " + prefix_name)
            print(str(jdout(resp)))
        else:
            print("Creating prefix name " + prefix_name)
    else:
        if ipv4_addresses == prefix_data["ipv4_prefixes"]:
            print("O365-Prefix are still up to date")
        else:
            data = prefix_data 
            data["ipv4_prefixes"] = ipv4_addresses
        
            resp = cgx.put.networkpolicyglobalprefixes(networkpolicyglobalprefix_id=data["id"],data=data)
            if not resp:
                print("ERROR updating prefix " + prefix_name)
                print(str(jdout(resp)))
            else:
                print("Updating prefix name " + prefix_name)
            
    
    return
                                 
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "Alpha: https://api-alpha.elcapitan.cloudgenix.com"
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)
    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)
    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)
                             
    args = vars(parser.parse_args())
    
    ############################################################################
    # Instantiate API
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ##
    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    cgx = cgx_session

    schedule.every(5).minutes.do(o365, cgx)
    while True:
        schedule.run_pending()
        time.sleep(60)

if __name__ == "__main__":
    go()