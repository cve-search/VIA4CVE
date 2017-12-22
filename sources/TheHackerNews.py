#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# TheHackerNews information
#   Based on Vulners
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2017 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Sources
SOURCE_NAME = 'the hacker news'
SOURCE_FILE = "https://vulners.com/api/v3/archive/collection/?type=thn"

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

class TheHackerNews(Source):
    def __init__(self):
        self.name = SOURCE_NAME
        self.cves = defaultdict(list)

        _file, r = conf.getFeedData(SOURCE_NAME, SOURCE_FILE)
        data = json.loads(str(_file.read(), 'utf-8'))
        for entry in data:
            thn = {}
            source = entry['_source']
            add_if(thn, source, 'published')
            add_if(thn, source, 'modified')
            add_if(thn, source, 'lastseen', 'last seen')
            add_if(thn, source, 'id')
            add_if(thn, source, 'title')
            add_if(thn, source, 'references')
            add_if(thn, source, 'reporter')
            add_if(thn, source, 'href', 'source')

            for date in ['published', 'modified', 'last seen']: clean_date(thn, date)
            if thn:
                for CVE in source['cvelist']: self.cves[CVE].append(thn)

    def getSearchables(self):
        return ['id', 'reporter']
