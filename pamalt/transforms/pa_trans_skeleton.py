#!/usr/bin/env python

import urllib, urllib2
import time
import xml.etree.ElementTree as ET

from pamalt.lib import pamod

def test_mod():
    pa_hostname = 'isdpan1295'
    key = pamod.pa_auth('papi_user', 'p@ssw0rd', pa_hostname)
    print key


