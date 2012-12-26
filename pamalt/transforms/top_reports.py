#!/usr/bin/env python
# Copyright (C) 2012 pamalt Developer.
# This file is part of pamalt - https://github.com/bostonlink/pamalt
# See the file 'LICENSE' for copying permission.

# Palo Alto top reports transform module
# Author: David Bressler (@bostonlink)

import urllib, urllib2
import time
import xml.etree.ElementTree as ET

from pamalt.lib import pamod

# PA Predefined Top reports

# Top attackers returns the top attacking IP addresses within the last 24 hours
# TODO must create a pamalt.topAttackers entity to run this transform off of.

def pre_top_attackers(pa_hostname, key):
    reportname = 'top-attackers'
    topattackers = pamod.pa_pred_report(pa_hostname, key, reportname)
     
    entry_list = []
    root = ET.fromstring(topattackers)

    for result in root:
        for entry in result:
            entry_dic = {}
            for data in entry:
                entry_dic[data.tag] = data.text

            entry_list.append(entry_dic)

    # Maltego XML Output
    print "<MaltegoMessage>\n<MaltegoTransformResponseMessage>"
    print "\t<Entities>"

    for dic in entry_list:
	
	print """	    <Entity Type="maltego.IPv4Address">
		<Value>%s</Value>
		<AdditionalFields>
		    <Field Name="count" DisplayName="Count">%s</Field>
		    <Field Name="user" DisplayName="User">%s</Field>
		    <Field Name="resolved" DisplayName="Resolved Hostname">%s</Field>
		</AdditionalFields> 
	    </Entity>""" % (dic['src'], dic['count'], dic['srcuser'], dic['resolved-src'])
	
    print "\t</Entities>"
    print "</MaltegoTransformResponseMessage>\n</MaltegoMessage>"

# Top attacks, returns top attacks for the last 24 hours
# by default PAN limits to 20 restults returned, report name: top-attacks

def pre_top_attacks(pa_hostname, key):
    reportname = 'top-attacks'
    topattacks = pamod.pa_pred_report(pa_hostname, key, reportname)

    entry_list = []
    root = ET.fromstring(topattacks)

    for result in root:
        for entry in result:
            entry_dic = {}

            for data in entry:
                entry_dic[data.tag] = data.text

            entry_list.append(entry_dic)
    
        # Maltego XML Output
    print "<MaltegoMessage>\n<MaltegoTransformResponseMessage>"
    print "\t<Entities>"

    for dic in entry_list:

        print """           <Entity Type="pamalt.paThreat">
                <Value>%s</Value>
                <AdditionalFields>
                    <Field Name="tid" DisplayName="Threat ID">%s</Field>
                    <Field Name="subtype" DisplayName="Subtype">%s</Field>
                    <Field Name="count" DisplayName="Count">%s</Field>
                </AdditionalFields> 
            </Entity>""" % (dic['threatid'], dic['tid'], dic['subtype'], dic['count'])

    print "\t</Entities>"
    print "</MaltegoTransformResponseMessage>\n</MaltegoMessage>"

# Top spyware threats, rturns top spyware threats for the last 24 hours
def pre_top_spyware(pa_hostname, key):
    reportname = 'top-spyware-threats'
    top_spyware = pamod.pa_pred_report(pa_hostname, key, reportname)

    entry_list = []
    root = ET.fromstring(top_spyware)

    for result in root:
        for entry in result:
            entry_dic = {}

            for data in entry:
                entry_dic[data.tag] = data.text

            entry_list.append(entry_dic)

        # Maltego XML Output
    print "<MaltegoMessage>\n<MaltegoTransformResponseMessage>"
    print "\t<Entities>"

    for dic in entry_list:

        print """           <Entity Type="pamalt.paThreat">
                <Value>%s</Value>
                <AdditionalFields>
                    <Field Name="tid" DisplayName="Threat ID">%s</Field>
                    <Field Name="count" DisplayName="Count">%s</Field>
                </AdditionalFields> 
            </Entity>""" % (dic['threatid'], dic['tid'], dic['count'])

    print "\t</Entities>"
    print "</MaltegoTransformResponseMessage>\n</MaltegoMessage>"

# Top Victims predefined report, returns top victims for the last 24 hours
def pre_top_vics(pa_hostname, key):
    reportname = 'top-victims'
    topvics = pamod.pa_pred_report(pa_hostname, key, reportname)

    entry_list = []
    root = ET.fromstring(topvics)

    for result in root:
        for entry in result:
            entry_dic = {}

            for data in entry:
                entry_dic[data.tag] = data.text

            entry_list.append(entry_dic)

        # Maltego XML Output
    print "<MaltegoMessage>\n<MaltegoTransformResponseMessage>"
    print "\t<Entities>"

    for dic in entry_list:

        print """           <Entity Type="maltego.IPv4Address">
                <Value>%s</Value>
                <AdditionalFields>
                    <Field Name="resolved" DisplayName="Resolved Hostname">%s</Field>
		    <Field Name="dtuser" DisplayName="UserName">%s</Field>
                    <Field Name="count" DisplayName="Count">%s</Field>
                </AdditionalFields> 
            </Entity>""" % (dic['dst'], dic['resolved-dst'], dic['dstuser'],dic['count'])

    print "\t</Entities>"
    print "</MaltegoTransformResponseMessage>\n</MaltegoMessage>"

# Top Viruses predefined report, returns top viruses for the last 24 hours
def pre_top_viruses(pa_hostname, key):
    reportname = 'top-viruses'
    topviruses = pamod.pa_pred_report(pa_hostname, key, reportname)

    entry_list = []
    root = ET.fromstring(topviruses)

    for result in root:
        for entry in result:
            entry_dic = {}

            for data in entry:
                entry_dic[data.tag] = data.text

            entry_list.append(entry_dic)
    
        # Maltego XML Output
    print "<MaltegoMessage>\n<MaltegoTransformResponseMessage>"
    print "\t<Entities>"

    for dic in entry_list:

        print """           <Entity Type="pamalt.paThreat">
                <Value>%s</Value>
                <AdditionalFields>
                    <Field Name="tid" DisplayName="Threat ID">%s</Field>
                    <Field Name="count" DisplayName="Count">%s</Field>
                </AdditionalFields> 
            </Entity>""" % (dic['threatid'], dic['tid'], dic['count'])

    print "\t</Entities>"
    print "</MaltegoTransformResponseMessage>\n</MaltegoMessage>"

# Top Vulnerabilities predefined report, returns top vulns for the last 24 hours
def pre_top_vulns(pa_hostname, key):
    reportname = 'top-vulnerabilities'
    topvulns = pamod.pa_pred_report(pa_hostname, key, reportname)

    entry_list = []
    root = ET.fromstring(topvulns)

    for result in root:
        for entry in result:
            entry_dic = {}

            for data in entry:
                entry_dic[data.tag] = data.text

            entry_list.append(entry_dic)
    
       # Maltego XML Output
    print "<MaltegoMessage>\n<MaltegoTransformResponseMessage>"
    print "\t<Entities>"

    for dic in entry_list:

        print """           <Entity Type="pamalt.paThreat">
                <Value>%s</Value>
                <AdditionalFields>
                    <Field Name="tid" DisplayName="Threat ID">%s</Field>
                    <Field Name="count" DisplayName="Count">%s</Field>
                </AdditionalFields> 
            </Entity>""" % (dic['threatid'], dic['tid'], dic['count'])

    print "\t</Entities>"
    print "</MaltegoTransformResponseMessage>\n</MaltegoMessage>"