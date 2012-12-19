#!/usr/bin/env python

# PaloAlto Networks API Python Module
# Author: David Bressler

import urllib2, urllib
import time
import xml.etree.ElementTree as ET

# Authenticates to PA API and returns API key for all API calls

def pa_auth(pausr, papass, pa_hostname):
    
    base_url = 'https://%s/api/?' % pa_hostname
    params_dic = {}
    params_dic['type'] = 'keygen'
    params_dic['user'] = pausr
    params_dic['password'] = papass

    enc_params = urllib.urlencode(params_dic)
    full_url = base_url + enc_params

    try:

        req = urllib2.Request(full_url)
        ret = urllib2.urlopen(req)
        ret_data = ret.read()
	# Start parsing the returned XML
	root = ET.fromstring(ret_data)
	auth_key = root[0][0].text
        return auth_key

    except urllib2.HTTPError as e:
	return e

# PA Dynamic report function, must provide a valid dynamic report name
# See pa_dyn_rname.txt list for all valid report names

def pa_dyn_report(pa_hostname, key, reportname, period=''):
    
    base_url = 'https://%s/api/?' % pa_hostname
    params_dic = {}
    params_dic['type'] = 'report'
    params_dic['reporttype'] = 'dynamic'
    params_dic['reportname'] = reportname
    params_dic['period'] = period
    params_dic['key'] = key

    enc_params = urllib.urlencode(params_dic)
    full_url = base_url + enc_params
    
    try:

        req = urllib2.Request(full_url)
        ret = urllib2.urlopen(req)
        ret_data = ret.read()
        return ret_data

    except urllib2.HTTPError as e:
        return e

# PA predefined report function, must provide a valid predefined report name

def pa_pred_report(pa_hostname, key, reportname):

    base_url = 'https://%s/api/?' % pa_hostname
    params_dic = {}
    params_dic['type'] = 'report'
    params_dic['reporttype'] = 'predefined'
    params_dic['reportname'] = reportname
    params_dic['key'] = key

    enc_params = urllib.urlencode(params_dic)
    full_url = base_url + enc_params

    try:

        req = urllib2.Request(full_url)
        ret = urllib2.urlopen(req)
        ret_data = ret.read()
        return ret_data

    except urllib2.HTTPError as e:
        return e

# PA log query function to query pa logs and return the results in XML format

def pa_log_query(pa_hostname, key, log_type, query=''):

    base_url = 'https://%s/api/?' % pa_hostname
    params_dic = {}
    params_dic['type'] = 'log'
    params_dic['logtype'] = log_type
    params_dic['query'] = query
    params_dic['key'] = key
    
    enc_params = urllib.urlencode(params_dic)
    full_url = base_url + enc_params

    try:

        req = urllib2.Request(full_url)
        ret = urllib2.urlopen(req)
        ret_data = ret.read()

    except urllib2.HTTPError as e:
        return e

    root = ET.fromstring(ret_data)
    job = root[0][1].text
    return job
    
def pa_log_get(pa_hostname, key, jobid):

    base_url = 'https://%s/api/?' % pa_hostname
    params_dic = {}
    params_dic['type'] = 'log'
    params_dic['action'] = 'get'
    params_dic['job-id'] = jobid
    params_dic['key'] = key

    enc_params = urllib.urlencode(params_dic)
    full_url = base_url + enc_params

    try:

        req = urllib2.Request(full_url)
        ret = urllib2.urlopen(req)
        ret_data = ret.read()
	return ret_data

    except urllib2.HTTPError as e:
        return e
