#!/usr/bin/env python3
import prisma_sase
import argparse
from prisma_sase import jd, jd_detailed, jdout
import prismasase_settings
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



# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from prismasase_settings import PRISMASASE_CLIENT_ID, PRISMASASE_CLIENT_SECRET, PRISMASASE_TSG_ID

except ImportError:
    PRISMASASE_CLIENT_ID=None
    PRISMASASE_CLIENT_SECRET=None
    PRISMASASE_TSG_ID=None

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
    
    ##### path prefix 
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
            print("ERROR creating path prefix " + prefix_name)
            print(str(jdout(resp)))
        else:
            print("Creating path prefix name " + prefix_name)
    else:
        if ipv4_addresses == prefix_data["ipv4_prefixes"]:
            print("O365-Prefix path is up to date")
        else:
            data = prefix_data 
            data["ipv4_prefixes"] = ipv4_addresses
        
            resp = cgx.put.networkpolicyglobalprefixes(networkpolicyglobalprefix_id=data["id"],data=data)
            if not resp:
                print("ERROR updating path prefix " + prefix_name)
                print(str(jdout(resp)))
            else:
                print("Updating path prefix name " + prefix_name)
                
    ##### security prefix    
    prefix_found = False
    prefix_data = None
    for item in cgx.get.ngfwsecuritypolicyglobalprefixes().cgx_content['items']:
        if item["name"] == prefix_name:
            prefix_found = True
            prefix_data = item
            
    
    if not prefix_found:
        data = {"name":prefix_name,"tags":[],"ipv4_prefixes":ipv4_addresses,"ipv6_prefixes":[],"description":None}
        
        resp = cgx.post.ngfwsecuritypolicyglobalprefixes(data=data)
        if not resp:
            print("ERROR creating security prefix " + prefix_name)
            print(str(jdout(resp)))
        else:
            print("Creating security prefix name " + prefix_name)
    else:
        if ipv4_addresses == prefix_data["ipv4_prefixes"]:
            print("O365-Prefix security is up to date")
        else:
            data = prefix_data 
            data["ipv4_prefixes"] = ipv4_addresses
        
            resp = cgx.put.ngfwsecuritypolicyglobalprefixes(ngfwsecuritypolicyglobalprefix_id=data["id"],data=data)
            if not resp:
                print("ERROR updating security prefix " + prefix_name)
                print(str(jdout(resp)))
            else:
                print("Updating security prefix name " + prefix_name)
    
    ##### qos prefix    
    prefix_found = False
    prefix_data = None
    for item in cgx.get.prioritypolicyglobalprefixes().cgx_content['items']:
        if item["name"] == prefix_name:
            prefix_found = True
            prefix_data = item
            
    
    if not prefix_found:
        data = {"name":prefix_name,"tags":[],"ipv4_prefixes":ipv4_addresses,"ipv6_prefixes":[],"description":None}
        
        resp = cgx.post.prioritypolicyglobalprefixes(data=data)
        if not resp:
            print("ERROR creating QoS prefix " + prefix_name)
            print(str(jdout(resp)))
        else:
            print("Creating QoS prefix name " + prefix_name)
    else:
        if ipv4_addresses == prefix_data["ipv4_prefixes"]:
            print("O365-Prefix QoS is up to date")
        else:
            data = prefix_data 
            data["ipv4_prefixes"] = ipv4_addresses
        
            resp = cgx.put.prioritypolicyglobalprefixes(prioritypolicyglobalprefix_id=data["id"],data=data)
            if not resp:
                print("ERROR updating QoS prefix " + prefix_name)
                print(str(jdout(resp)))
            else:
                print("Updating QoS prefix name " + prefix_name)
    
    ##### global prefix    
    prefix_found = False
    prefix_data = None
    for item in cgx.get.globalprefixfilters().cgx_content['items']:
        if item["name"] == prefix_name:
            prefix_found = True
            prefix_data = item
            
    
    if not prefix_found:
        data = {"name":prefix_name,"filters":[{"type":"ipv4","ip_prefixes":ipv4_addresses}],"description":None}

        
        resp = cgx.post.globalprefixfilters(data=data)
        if not resp:
            print("ERROR creating global prefix " + prefix_name)
            print(str(jdout(resp)))
        else:
            print("Creating global prefix name " + prefix_name)
    else:
        if ipv4_addresses == prefix_data["filters"][0]["ip_prefixes"]:
            print("O365-Prefix global is up to date")
        else:
            data = prefix_data 
            data["filters"][0]["ip_prefixes"] = ipv4_addresses
        
            resp = cgx.put.globalprefixfilters(globalprefixfilter_id=data["id"],data=data)
            if not resp:
                print("ERROR updating global prefix " + prefix_name)
                print(str(jdout(resp)))
            else:
                print("Updating global prefix name " + prefix_name)
            
    
    return
                                 
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # check for token
    sase_session = prisma_sase.API()
    #sase_session.set_debug(2)
    
    sase_session.interactive.login_secret(client_id=PRISMASASE_CLIENT_ID,
                                          client_secret=PRISMASASE_CLIENT_SECRET,
                                          tsg_id=PRISMASASE_TSG_ID)

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    cgx = sase_session
    o365(cgx)

    schedule.every(5).minutes.do(o365, cgx)
    while True:
        schedule.run_pending()
        time.sleep(60)

if __name__ == "__main__":
    go()
