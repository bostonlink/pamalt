#!/usr/bin/env python
# Copyright (C) 2012 pamalt Developer.
# This file is part of pamalt - https://github.com/bostonlink/pamalt
# See the file 'LICENSE' for copying permission.

# PaloAlto Networks Log Query Maltego Transforms
# Graphically visualize reports and logs from a PAN appliance
# Author: David Bressler (@bostonlink)

import urllib, urllib2
import sys,time
import xml.etree.ElementTree as ET
from optparse import OptionParser
import sys

from pamalt.lib import pamod
import pamalt.transforms.log_queries

# cmd line options parser

usage = """\n
pamalt.py - python PAN scripts and maltego transforms
Random:  Drink lots of whiskey and stay frosty!!

Author:  bostonlink
email:   bostonlink@pentest-labs.org
twitter: @bostonlink"""

parser = OptionParser(usage=usage)
parser.add_option("-t", action="store", dest="ip_address", help="IP Address to Threat", metavar="IP address")
parser.add_option("-s", action="store", dest="threatid", help="Threat to IP Source", metavar="Threat ID")
parser.add_option("-d", action="store", dest="tid", help="Threat to IP Destination", metavar="Threat ID")
(options, args) = parser.parse_args()

# Parse Configuration file
if os.name == 'posix':
    f = open('pamalt/conf/pamalt.conf', 'r')
    conf = f.readlines()
    f.close()
elif os.name == 'nt':
    f = open('pamalt\\conf\\pamalt.conf', 'r')
    conf = f.readlines()
    f.close()

key_active = False

for line in conf:
    if 'KEY:' in line:
        line_list = line.strip().split(':')
        key = line_list[1]
        key_active = True
    else:
        if 'PA_USER=' in line:
            line_list = line.strip().split('=')
            pa_user = line_list[1]
        elif 'PA_PASS=' in line:
            line_list = line.strip().split('=')
            pa_pass = line_list[1]
        elif 'HOSTNAME=' in line:
            line_list = line.strip().split('=')
            hostname = line_list[1]

if key_active != True:
    key = pamod.pa_auth(pa_user, pa_pass, hostname)
    f = open('pamalt/conf/pamalt.conf', 'w')
    f.write('# PAMALT configuration file overwritten with API key\n')
    f.write('# username and password was overwritten only need to change when API user password is changed\n')
    f.write('KEY:' + key + '\n')
    f.write('HOSTNAME=' + hostname + '\n')
    f.close()

if options.ip_address:
    pamalt.transforms.log_queries.ip_2_threat(hostname, key, options.ip_address)

elif options.threatid:
    args = sys.argv[3]
    add_list = args.split('#')
    for field in add_list:
	if 'tid' in field:
	    parse = field.split('=')
	    tid = parse[1]

    pamalt.transforms.log_queries.threat_2_ipsrc(hostname, key, tid)

elif options.tid:
    args = sys.argv[3]
    add_list = args.split('#')
    for field in add_list:
        if 'tid' in field:
            parse = field.split('=')
            tid = parse[1]
    
    pamalt.transforms.log_queries.threat_2_ipdst(hostname, key, tid)
