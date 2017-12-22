#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Metasploit information
#   Based on Vulners
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2017 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Sources
SOURCE_NAME = 'metasploit'
SOURCE_FILE = "https://vulners.com/api/v3/archive/collection/?type=metasploit"

# Imports
import json

from collections import defaultdict

from lib.Config import Configuration as conf
from lib.Source import Source

def add_if(_, entry, item, name=None):
    if not name: name=item
    if entry.get(item): _[name] = entry[item]

def clean_date(_, item):
    if _.get(item): _[item] = _[item].split('T')[0]

class Metasploit(Source):
    def __init__(self):
        self.name = SOURCE_NAME
        self.cves = defaultdict(list)

        _file, r = conf.getFeedData(SOURCE_NAME, SOURCE_FILE)
        data = json.loads(str(_file.read(), 'utf-8'))
        for entry in data:
            msf = {}
            source = entry['_source']
            add_if(msf, source, 'published')
            add_if(msf, source, 'modified')
            add_if(msf, source, 'lastseen', 'last seen')
            add_if(msf, source, 'metasploitReliability', 'reliability')
            add_if(msf, source, 'id')
            add_if(msf, source, 'title')
            add_if(msf, source, 'description')
            add_if(msf, source, 'references')
            add_if(msf, source, 'reporter')
            add_if(msf, source, 'sourceHref', 'source')

            for date in ['published', 'modified', 'last seen']: clean_date(msf, date)
            if msf:
                for CVE in source['cvelist']: self.cves[CVE].append(msf)

    def getSearchables(self):
        return ['id', 'reporter']
