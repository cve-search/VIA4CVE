#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Source file for the Seebug information
#
# Based on Vulners.com
# Software is free software released under the GNU Affero General Public License v3.0
#
# CriimBow - ggranjon@student.le-101.fr


# Import
import json
from collections import defaultdict
from lib.Config import Configuration as conf
from lib.Source import Source

# Sources
SOURCE_NAME = 'Seebug'
SOURCE_FILE = "https://vulners.com/api/v3/archive/collection/?type=seebug"

def add_if(_, entry, item, name=None):
    if not name:
      name = item
    if entry.get(item):
        _[name] = entry[item]

def clean_date(_, item):
    if _.get(item):
        _[item] = _[item].split('T')[0]

class Seebug(Source):
    def __init__(self):
        self.name = SOURCE_NAME
        self.cves = defaultdict(list)

        _file, r = conf.getFeedData(SOURCE_NAME, SOURCE_FILE)
        data = json.loads(str(_file.read(), 'utf-8'))
        for entry in data:
            sbg = {}
            source = entry['_source']
            add_if(sbg, source, 'published')
            add_if(sbg, source, 'modified')
            add_if(sbg, source, 'lastseen', 'last seen')
            add_if(sbg, source, 'id')
            add_if(sbg, source, 'title')
            add_if(sbg, source, 'bulletinFamily')
            add_if(sbg, source, 'description')
            add_if(sbg, source, 'references')
            add_if(sbg, source, 'reporter')
            add_if(sbg, source, 'sourceHref', 'source')

            for date in ['published', 'modified', 'last seen']:
                clean_date(sbg, date)
            if sbg:
                for CVE in source['cvelist']: self.cves[CVE].append(sbg)

    def getSearchables(self):
        return ['id', 'reporter']
