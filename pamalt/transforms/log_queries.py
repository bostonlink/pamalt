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
    logtype = 'threat'
    query = '(addr.dst in %s) or (addr.src in %s)' % (ip, ip)
    jobid = pamod.pa_log_query(pa_hostname, key, logtype, query)
    time.sleep(5)
    result = pamod.pa_log_get(pa_hostname, key, jobid)
 
    root = ET.fromstring(result)
    # Parse the job status from the intitial pull of the job
    for result in root:
        for job in result:

            if job.tag == 'job':
                job_dic = {}
                for data in job:
                    job_dic[data.tag] = data.text

    # Check the status of the job until it is finished
    while job_dic['status'] == 'ACT':
        time.sleep(10)
        response = pamod.pa_log_get(pa_hostname, key, jobid)
	root = ET.fromstring(response)

	for result in root:
	    for job in result:

		if job.tag == 'job':
		    job_dic = {}
		    for data in job:
			job_dic[data.tag] = data.text
	continue

	if job_dic['status'] == 'FIN':
	    root = ET.fromstring(results)
	    break

    # parse the log data and create dictionaries stored in a list for each individual log
    for response in root:
	for result in response:
	    if result.tag == 'log':
		for log in result:
		    logs = log
    log_list = []
    for entry in logs:
	entry_dic = {}
	for data in entry:
	    entry_dic[data.tag] = data.text
    
	log_list.append(entry_dic)
    
    threat_list = []

    # Maltego XML Output
    print "<MaltegoMessage>\n<MaltegoTransformResponseMessage>"
    print "\t<Entities>"

    for dic in log_list:
	if dic['threatid'] in threat_list:
	    continue
	else:

            print """           <Entity Type="pamalt.paThreat">
	            <Value>%s</Value>
	            <AdditionalFields>
		        <Field Name="ipsrc" DisplayName="IP Source">%s</Field>
		        <Field Name="ipdst" DisplayName="IP Destination">%s</Field>
			<Field Name="tid" DisplayName="Threat ID">%s</Field>
		    </AdditionalFields> 
		</Entity>""" % (dic['threatid'], dic['src'], dic['dst'], dic['tid'])

	threat_list.append(dic['threatid'])
    print "\t</Entities>"
    print "</MaltegoTransformResponseMessage>\n</MaltegoMessage>"

def threat_2_ipsrc(pa_hostname, key, tid):
    logtype = 'threat'
    query = '(threatid eq %s)' % (tid)
    jobid = pamod.pa_log_query(pa_hostname, key, logtype, query)
    time.sleep(5)
    result = pamod.pa_log_get(pa_hostname, key, jobid)

    root = ET.fromstring(result)
    # Parse the job status from the intitial pull of the job
    for result in root:
        for job in result:

            if job.tag == 'job':
                job_dic = {}
                for data in job:
                    job_dic[data.tag] = data.text

    # Check the status of the job until it is finished
    while job_dic['status'] == 'ACT':
        time.sleep(10)
        response = pamod.pa_log_get(pa_hostname, key, jobid)
        root = ET.fromstring(response)

        for result in root:
            for job in result:

                if job.tag == 'job':
                    job_dic = {}
                    for data in job:
                        job_dic[data.tag] = data.text
        continue

        if job_dic['status'] == 'FIN':
            root = ET.fromstring(results)
            break

    # parse the log data and create dictionaries stored in a list for each individual log
    for response in root:
        for result in response:
            if result.tag == 'log':
                for log in result:
                    logs = log
    log_list = []
    for entry in logs:
        entry_dic = {}
        for data in entry:
            entry_dic[data.tag] = data.text

        log_list.append(entry_dic)

    ip_list = []

    # Maltego XML Output
    print "<MaltegoMessage>\n<MaltegoTransformResponseMessage>"
    print "\t<Entities>"

    for dic in log_list:
        if dic['src'] in ip_list:
            continue
        else:

            print """           <Entity Type="maltego.IPv4Address">
                    <Value>%s</Value>
                    <AdditionalFields>
                        <Field Name="ipdst" DisplayName="IP Destination">%s</Field>
                        <Field Name="tid" DisplayName="Threat ID">%s</Field>
                    </AdditionalFields> 
                </Entity>""" % (dic['src'], dic['dst'], dic['tid'])

        ip_list.append(dic['src'])
    print "\t</Entities>"
    print "</MaltegoTransformResponseMessage>\n</MaltegoMessage>"

def threat_2_ipdst(pa_hostname, key, tid):
    logtype = 'threat'
    query = '(threatid eq %s)' % (tid)
    jobid = pamod.pa_log_query(pa_hostname, key, logtype, query)
    time.sleep(5)
    result = pamod.pa_log_get(pa_hostname, key, jobid)

    root = ET.fromstring(result)
    # Parse the job status from the intitial pull of the job
    for result in root:
        for job in result:

            if job.tag == 'job':
                job_dic = {}
                for data in job:
                    job_dic[data.tag] = data.text

    # Check the status of the job until it is finished
    while job_dic['status'] == 'ACT':
        time.sleep(10)
        response = pamod.pa_log_get(pa_hostname, key, jobid)
        root = ET.fromstring(response)

        for result in root:
            for job in result:

                if job.tag == 'job':
                    job_dic = {}
                    for data in job:
                        job_dic[data.tag] = data.text
        continue

        if job_dic['status'] == 'FIN':
            root = ET.fromstring(results)
            break

    # parse the log data and create dictionaries stored in a list for each individual log
    for response in root:
        for result in response:
            if result.tag == 'log':
                for log in result:
                    logs = log
    log_list = []
    for entry in logs:
        entry_dic = {}
        for data in entry:
            entry_dic[data.tag] = data.text

        log_list.append(entry_dic)

    ip_list = []

    # Maltego XML Output
    print "<MaltegoMessage>\n<MaltegoTransformResponseMessage>"
    print "\t<Entities>"

    for dic in log_list:
        if dic['dst'] in ip_list:
            continue
        else:

            print """           <Entity Type="maltego.IPv4Address">
                    <Value>%s</Value>
                    <AdditionalFields>
                        <Field Name="ipdst" DisplayName="IP Source">%s</Field>
                        <Field Name="tid" DisplayName="Threat ID">%s</Field>
                    </AdditionalFields> 
                </Entity>""" % (dic['dst'], dic['src'], dic['tid'])

        ip_list.append(dic['dst'])
    print "\t</Entities>"
    print "</MaltegoTransformResponseMessage>\n</MaltegoMessage>"
