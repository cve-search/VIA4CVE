#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# VulnerLab information
#   Based on Vulners
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2017 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Sources
SOURCE_NAME = 'vulner lab'
SOURCE_FILE = "https://vulners.com/api/v3/archive/collection/?type=vulnerlab"

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

class VulnerLab(Source):
    def __init__(self):
        self.name = SOURCE_NAME
        self.cves = defaultdict(list)

        _file, r = conf.getFeedData(SOURCE_NAME, SOURCE_FILE)
        data = json.loads(str(_file.read(), 'utf-8'))
        for entry in data:
            lab = {}
            source = entry['_source']
            add_if(lab, source, 'published')
            add_if(lab, source, 'modified')
            add_if(lab, source, 'lastseen', 'last seen')
            add_if(lab, source, 'id')
            add_if(lab, source, 'title')
            add_if(lab, source, 'references')
            add_if(lab, source, 'reporter')
            add_if(lab, source, 'href', 'source')

            for date in ['published', 'modified', 'last seen']: clean_date(lab, date)
            if lab:
                for CVE in source['cvelist']: self.cves[CVE].append(lab)
