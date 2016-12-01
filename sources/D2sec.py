#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Source file for d2sec exploit information
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016    Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Sources
SOURCE_NAME = 'd2sec'
SOURCE_FILE = "https://www.d2sec.com/exploits/elliot.xml"

# Imports
import copy
from collections     import defaultdict
from xml.sax         import make_parser
from xml.sax.handler import ContentHandler

from lib.Config import Configuration as conf
from lib.Source import Source

class D2secHandler(ContentHandler):
  def __init__(self):
    self.exploits = []
    self.d2sec    = None
    self.tag      = None

  def startElement(self, name, attrs):
    self.tag = name
    if   name == 'exploit': self.d2sec={'refs':[]}
    elif name == 'ref':
      self.d2sec['refs'].append({'type': attrs.get('type').lower()})

  def characters(self, ch):
    if self.d2sec and self.tag:
      if   self.tag == 'ref':     self.d2sec['refs'][-1]['key'] = ch
      elif self.tag != "exploit": self.d2sec[self.tag] = ch

  def endElement(self, name):
    self.tag = None
    if   name == 'exploit' and self.d2sec:
      self.exploits.append(self.d2sec)
      self.saint = None


class D2sec(Source):
  def __init__(self):
    self.name = SOURCE_NAME
    parser    = make_parser()
    handler = D2secHandler()
    _file, r = conf.getFeedData(SOURCE_NAME, SOURCE_FILE)
    parser.setContentHandler(handler)
    parser.parse(_file)
    self.cves     = defaultdict(list)
    self.exploits = defaultdict(dict)
    for exploit in handler.exploits:
      _exploit = copy.copy(exploit) # clean exploit to add to the list
      _exploit.pop('refs')
      for ref in exploit.get('refs', []):
        if ref['type'] == 'cve': self.cves[ref['key']].append(_exploit)
        else:
          if ref['key'] not in self.exploits[ref['type']]:
            self.exploits[ref['type']][ref['key']] = []
          self.exploits[ref['type']][ref['key']].append(_exploit)

  def updateRefs(self, cveID, cveData):
    if not cveData.get(SOURCE_NAME): cveData[SOURCE_NAME] = []
    for key in cveData.get('refmap', {}).keys():
      for _id in cveData['refmap'][key]:
        cveData[SOURCE_NAME].extend(self.exploits[key].get(_id, []))
    if cveData[SOURCE_NAME] == []: cveData.pop(SOURCE_NAME)
