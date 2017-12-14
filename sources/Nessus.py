#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Nessus information
#   Based on Vulners
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2017 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Sources
SOURCE_NAME = 'nessus'
SOURCE_FILE = "https://vulners.com/api/v3/archive/collection/?type=nessus"

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

class Nessus(Source):
    def __init__(self):
        self.name = SOURCE_NAME
        self.cves = defaultdict(list)

        _file, r = conf.getFeedData(SOURCE_NAME, SOURCE_FILE)
        data = json.loads(str(_file.read(), 'utf-8'))
        for entry in data:
            nessus = {}
            source = entry['_source']
            add_if(nessus, source, 'published')
            add_if(nessus, source, 'modified')
            add_if(nessus, source, 'lastseen', 'last seen')
            add_if(nessus, source, 'pluginID', 'plugin id')
            add_if(nessus, source, 'title')
            add_if(nessus, source, 'description')
            add_if(nessus, source, 'naslFamily', 'NASL family')
            add_if(nessus, source, 'id', 'NASL id')
            add_if(nessus, source, 'href', 'source')
            add_if(nessus, source, 'reporter')

            for date in ['published', 'modified', 'last seen']: clean_date(nessus, date)
            if nessus:
                for CVE in source['cvelist']: self.cves[CVE].append(nessus)
