#!/usr/bin/env python
# Copyright (C) 2012 pamalt Developer.
# This file is part of pamalt - https://github.com/bostonlink/pamalt
# See the file 'LICENSE' for copying permission.

# PaloAlto Networks API Python Module
# Author: David Bressler

import urllib2, urllib
import time
import xml.etree.ElementTree as ET

def http_get(full_url):
    try:
        req = urllib2.Request(full_url)
        ret = urllib2.urlopen(req)
        return ret.read()
    except urllib2.HTTPError as e:
        return e

# Authenticates to PA API and returns API key for all API calls

def pa_auth(pausr, papass, pa_hostname):
    
    base_url = 'https://%s/api/?' % pa_hostname
    params_dic = {'type': 'keygen', 'user': pausr, 'password': papass}

    enc_params = urllib.urlencode(params_dic)
    full_url = base_url + enc_params
    ret_data = http_get(full_url)
    root = ET.fromstring(ret_data)
    return root[0][0].text

# PA Dynamic report function, must provide a valid dynamic report name
# See pa_dyn_rname.txt list for all valid report names

def pa_dyn_report(pa_hostname, key, reportname, period=''):
    
    base_url = 'https://%s/api/?' % pa_hostname
    params_dic = {'type': 'report', 'reporttype': 'dynamic', 'reportname': reportname, 'period': period, 'key': key}

    enc_params = urllib.urlencode(params_dic)
    full_url = base_url + enc_params
    return http_get(full_url)

# PA predefined report function, must provide a valid predefined report name

def pa_pred_report(pa_hostname, key, reportname):

    base_url = 'https://%s/api/?' % pa_hostname
    params_dic = {'type': 'report', 'reporttype': 'predefined', 'reportname': reportname, 'key': key}

    enc_params = urllib.urlencode(params_dic)
    full_url = base_url + enc_params
    return http_get(full_url)

# PA log query function to query pa logs and return the results in XML format

def pa_log_query(pa_hostname, key, log_type, query=''):

    base_url = 'https://%s/api/?' % pa_hostname
    params_dic = {'type': 'log', 'logtype': log_type, 'query': query, 'key': key}
    
    enc_params = urllib.urlencode(params_dic)
    full_url = base_url + enc_params
    ret_data = http_get(full_url)
    root = ET.fromstring(ret_data)
    return root[0][1].text
    
def pa_log_get(pa_hostname, key, jobid):

    base_url = 'https://%s/api/?' % pa_hostname
    params_dic = {'type': 'log', 'action': 'get', 'job-id': jobid, 'key': key}

    enc_params = urllib.urlencode(params_dic)
    full_url = base_url + enc_params
    return http_get(full_url)