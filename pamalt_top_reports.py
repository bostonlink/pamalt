#!/usr/bin/env python

# PaloAlto Networks Maltego Transforms
# Graphically visualize reports and logs from a PAN appliance
# Author: David Bressler

import urllib, urllib2
import sys,time
import xml.etree.ElementTree as ET
from optparse import OptionParser

from pamalt.lib import pamod
import pamalt.transforms.top_reports

# cmd line options parser

usage = """\n
pamalt.py - python PAN scripts and maltego transforms
Random:  Drink lots of whiskey and stay frosty!!

Author:  bostonlink
email:   bostonlink@pentest-labs.org
twitter: @bostonlink"""

parser = OptionParser(usage=usage)
parser.add_option("--top-attackers", action="store_true", dest="top_attackers", help="Returns a Top attackers predefined report")
parser.add_option("--top-attacks", action="store_true", dest="top_attacks", help="Returns a Top Attacks predefined report")
parser.add_option("--top-spyware", action="store_true", dest="top_spyware", help="Returns a Top Spyware Threats predefined report")
parser.add_option("--top-victims", action="store_true", dest="top_victims", help="Returns a Top Victims predefined report")
parser.add_option("--top-viruses", action="store_true", dest="top_viruses", help="Returns a Top Viruses predefined report")
parser.add_option("--top-vulnerabilities", action="store_true", dest="top_vulns", help="Returns a Top Vulnerabilities predefined report")
(options, args) = parser.parse_args()

# Parse Configuration file
f = open('pamalt/conf/pamalt.conf', 'r')
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

# Check command line option(s)
if options.top_attackers:
    pamalt.transforms.top_reports.pre_top_attackers(hostname, key)

elif options.top_attacks:
    pamalt.transforms.top_reports.pre_top_attacks(hostname, key)

elif options.top_spyware:
    pamalt.transforms.top_reports.pre_top_spyware(hostname, key)

elif options.top_victims:
    pamalt.transforms.top_reports.pre_top_vics(hostname, key)

elif options.top_viruses:
    pamalt.transforms.top_reports.pre_top_viruses(hostname, key)

elif options.top_vulns:
    pamalt.transforms.top_reports.pre_top_vulns(hostname, key)

