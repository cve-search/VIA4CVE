#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Source file for saint exploit information
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016    Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Sources
SOURCE_NAME = 'saint'
SOURCE_FILE = "https://www.saintcorporation.com/xml/exploits.xml"

# Imports
from collections     import defaultdict
from xml.sax         import make_parser
from xml.sax.handler import ContentHandler

from lib.Config import Configuration as conf
from lib.Source import Source

class SaintHandler(ContentHandler):
  def __init__(self):
    self.exploits = []
    self.saint    = None
    self.tag      = None

  def startElement(self, name, attrs):
    self.tag = name
    if   name == 'exploit':
      self.saint={}
      if attrs.get('id'): self.saint['title']=attrs.get('id')

  def characters(self, ch):
    if self.tag == 'saint_id': self.saint['id']     = ch
    elif self.tag and self.tag != "exploit" and self.saint and ch:
      self.saint[self.tag] = ch

  def endElement(self, name):
    self.tag = None
    if   name == 'exploit' and self.saint:
      self.exploits.append(self.saint)
      self.saint = None


class Saint(Source):
  def __init__(self):
    self.name = SOURCE_NAME
    parser    = make_parser()
    handler = SaintHandler()
    _file, r = conf.getFeedData(SOURCE_NAME, SOURCE_FILE)
    parser.setContentHandler(handler)
    parser.parse(_file)
    self.cves   = defaultdict(list)
    self.bids   = defaultdict(list)
    self.osvdbs = defaultdict(list)
    for exploit in handler.exploits:
      if exploit.get('cve'):   self.cves[  exploit['cve']  ].append(exploit)
      if exploit.get('bid'):   self.bids[  exploit['bid']  ].append(exploit)
      if exploit.get('osvdb'): self.osvdbs[exploit['osvdb']].append(exploit)

  def updateRefs(self, cveID, cveData):
    cveData['saint'] = []
    # Map osvdb, bid and cve
    _bids   = cveData.get('refmap', {}).get('bid',   {})
    _osvdbs = cveData.get('refmap', {}).get('osvdb', {})
    cveData['saint'].extend(self.cves[cveID])
    
    for bid   in _bids:   cveData['saint'].extend(self.bids[bid])
    for osvdb in _osvdbs: cveData['saint'].extend(self.osvdbs[osvdb])
    # make unique
    cveData['saint'] = [dict(t) for t in set([tuple(d.items()) for d in cveData['saint']])]
    # Remove refmap items
    if cveData.get('refmap'):
      for exploit in cveData['saint']:
        if exploit.get('bid')   in cveData['refmap'].get('bid',   []):
          cveData['refmap']['bid'].remove(exploit.get('bid'))
          if len(cveData['refmap']['bid']) == 0: del cveData['refmap']['bid']
        if exploit.get('osvdb') in cveData['refmap'].get('osvdb', []):
          cveData['refmap']['osvdb'].remove(exploit.get('osvdb'))
          if len(cveData['refmap']['osvdb']) == 0: del cveData['refmap']['osvdb']
    if cveData['saint'] == []: cveData.pop('saint')
    return cveData
