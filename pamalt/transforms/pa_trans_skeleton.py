#!/usr/bin/env python
# Copyright (C) 2012 nwmaltego Developer.
# This file is part of pamalt - https://github.com/bostonlink/nwmaltego
# See the file 'LICENSE' for copying permission.

# Skeleton transform
# Author: David Bressler (bostonlink)
import urllib, urllib2
import time
import xml.etree.ElementTree as ET

from pamalt.lib import pamod

def test_mod():
    pa_hostname = 'isdpan1295'
    key = pamod.pa_auth('papi_user', 'p@ssw0rd', pa_hostname)
    print key