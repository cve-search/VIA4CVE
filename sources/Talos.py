#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Talos information
#   Based on Vulners
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2017 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Sources
SOURCE_NAME = 'talos'
SOURCE_FILE = "https://vulners.com/api/v3/archive/collection/?type=talos"

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

class Talos(Source):
    def __init__(self):
        self.name = SOURCE_NAME
        self.cves = defaultdict(list)

        _file, r = conf.getFeedData(SOURCE_NAME, SOURCE_FILE)
        data = json.loads(str(_file.read(), 'utf-8'))
        for entry in data:
            talos = {}
            source = entry['_source']
            add_if(talos, source, 'published')
            add_if(talos, source, 'lastseen', 'last seen')
            add_if(talos, source, 'id')
            add_if(talos, source, 'title')
            add_if(talos, source, 'references')
            add_if(talos, source, 'reporter')
            add_if(talos, source, 'href', 'source')

            for date in ['published', 'last seen']: clean_date(talos, date)
            if talos:
                for CVE in source['cvelist']: self.cves[CVE].append(talos)
