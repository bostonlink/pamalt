#!/usr/bin/env python
# Copyright (C) 2012 pamalt Developer.
# This file is part of pamalt - https://github.com/bostonlink/pamalt
# See the file 'LICENSE' for copying permission.

# PaloAlto Log query Maltego transforms module
# Author: David Bressler (@bostonlink)

import urllib, urllib2
import time, sys
import xml.etree.ElementTree as ET

from pamalt.lib import pamod

# Threat Log queries

def ip_2_threat(pa_hostname, key, ip):
    query = '(addr.dst in %s) or (addr.src in %s)' % (ip, ip)
    jobid = pamod.pa_log_query(pa_hostname, key, 'threat', query)
    time.sleep(5)
     
    # Loop function to check if the log query job is done
    root = ET.fromstring(pamod.pa_log_get(pa_hostname, key, jobid))
    for status in root.findall(".//job/status"):
        while status.text == 'ACT':
            time.sleep(5)
            root = ET.fromstring(pamod.pa_log_get(pa_hostname, key, jobid))
            for status in root.findall(".//job/status"):
                if status.text == 'FIN':
                    break

    # parse the log data and create dictionaries stored in a list for each individual log
    log_list = []
    for entry in root.findall(".//log/logs/entry"):
        entry_dic = {}
        for data in entry:
            entry_dic[data.tag] = data.text

        log_list.append(entry_dic)
    
    # Maltego XML Output
    print "<MaltegoMessage>\n<MaltegoTransformResponseMessage>"
    print " <Entities>"

    threat_list = []
    for dic in log_list:
        if dic['threatid'] in threat_list:
            continue
        else:

            print """       <Entity Type="pamalt.paThreat">
            <Value>%s</Value>
	            <AdditionalFields>
                    <Field Name="ipsrc" DisplayName="IP Source">%s</Field>
                    <Field Name="ipdst" DisplayName="IP Destination">%s</Field>
                    <Field Name="tid" DisplayName="Threat ID">%s</Field>
                </AdditionalFields> 
        </Entity>""" % (dic['threatid'], dic['src'], dic['dst'], dic['tid'])

        threat_list.append(dic['threatid'])
    print " </Entities>"
    print "</MaltegoTransformResponseMessage>\n</MaltegoMessage>"

def threat_2_ipsrc(pa_hostname, key, tid):
    query = '(threatid eq %s)' % (tid)
    jobid = pamod.pa_log_query(pa_hostname, key, 'threat', query)
    time.sleep(5)
    
    # Loop function to check if the log query job is done
    root = ET.fromstring(pamod.pa_log_get(pa_hostname, key, jobid))
    for status in root.findall(".//job/status"):
        while status.text == 'ACT':
            time.sleep(5)
            root = ET.fromstring(pamod.pa_log_get(pa_hostname, key, jobid))
            for status in root.findall(".//job/status"):
                if status.text == 'FIN':
                    break

    # parse the log data and create dictionaries stored in a list for each individual log
    log_list = []
    for entry in root.findall(".//log/logs/entry"):
        entry_dic = {}
        for data in entry:
            entry_dic[data.tag] = data.text

        log_list.append(entry_dic)
    
    # Maltego XML Output
    print "<MaltegoMessage>\n<MaltegoTransformResponseMessage>"
    print " <Entities>"
    
    ip_list = []
    for dic in log_list:
        if dic['src'] in ip_list:
            continue
        else:

            print """       <Entity Type="maltego.IPv4Address">
                    <Value>%s</Value>
                    <AdditionalFields>
                        <Field Name="ipdst" DisplayName="IP Destination">%s</Field>
                        <Field Name="tid" DisplayName="Threat ID">%s</Field>
                    </AdditionalFields> 
                </Entity>""" % (dic['src'], dic['dst'], dic['tid'])

        ip_list.append(dic['src'])
    print " </Entities>"
    print "</MaltegoTransformResponseMessage>\n</MaltegoMessage>"

def threat_2_ipdst(pa_hostname, key, tid):
    query = '(threatid eq %s)' % (tid)
    jobid = pamod.pa_log_query(pa_hostname, key, 'threat', query)
    time.sleep(5)
    
    # Loop function to check if the log query job is done
    root = ET.fromstring(pamod.pa_log_get(pa_hostname, key, jobid))
    for status in root.findall(".//job/status"):
        while status.text == 'ACT':
            time.sleep(5)
            root = ET.fromstring(pamod.pa_log_get(pa_hostname, key, jobid))
            for status in root.findall(".//job/status"):
                if status.text == 'FIN':
                    break

    # parse the log data and create dictionaries stored in a list for each individual log
    log_list = []
    for entry in root.findall(".//log/logs/entry"):
        entry_dic = {}
        for data in entry:
            entry_dic[data.tag] = data.text

        log_list.append(entry_dic)

    # Maltego XML Output
    print "<MaltegoMessage>\n<MaltegoTransformResponseMessage>"
    print " <Entities>"
    
    ip_list = []
    for dic in log_list:
        if dic['dst'] in ip_list:
            continue
        else:

            print """       <Entity Type="maltego.IPv4Address">
                    <Value>%s</Value>
                    <AdditionalFields>
                        <Field Name="ipdst" DisplayName="IP Source">%s</Field>
                        <Field Name="tid" DisplayName="Threat ID">%s</Field>
                    </AdditionalFields> 
                </Entity>""" % (dic['dst'], dic['src'], dic['tid'])

        ip_list.append(dic['dst'])
    print " </Entities>"
    print "</MaltegoTransformResponseMessage>\n</MaltegoMessage>"