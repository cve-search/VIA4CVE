#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Source file for OVAL information
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016    Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Sources
SOURCE_NAME = 'oval'
SOURCE_FILE = "https://oval.cisecurity.org/repository/download/5.11.1/all/oval.xml.zip"

# Imports
from collections     import defaultdict
from io              import BytesIO
from xml.sax         import make_parser
from xml.sax.handler import ContentHandler

from lib.Config import Configuration as conf
from lib.Source import Source

class OVALHandler(ContentHandler):
  def __init__(self):
    self.ovals   = {}
    self.oval_id = None
    self.tag     = None
    self.data    = None
    
    self.ovalstack = None

  def startElement(self, name, attrs):
    name = name.replace('oval-def:', '')
    self.tag = name
    if   name == 'definition':
      self.oval_id = attrs.get('id')
      self.ovals[self.oval_id] = {'id':           self.oval_id,
                                  'class':        attrs.get('class'),
                                  'version':      attrs.get('version'),
                                  'contributors': []}
    elif name == 'affected'          and self.oval_id:
      self.ovals[self.oval_id]['family'] = attrs.get('family')
    elif name == 'submitted'         and self.oval_id:
      self.ovals[self.oval_id]['submitted'] = attrs.get('date')
    elif name == 'contributor'       and self.oval_id:
      self.data = {'organization': attrs.get('organization')}
    elif name == 'status_change'     and self.oval_id:
      self.data = attrs.get('date')
    elif name == 'extend_definition' and self.oval_id:
      if not self.ovals[self.oval_id].get('definition_extensions'):
        self.ovals[self.oval_id]['definition_extensions'] = []
      data = {'comment': attrs.get('comment'), 'oval': attrs.get('definition_ref')}
      self.ovals[self.oval_id]['definition_extensions'].append(data)

    # Oval
    elif name == 'criteria' and self.oval_id:
      data = {"operator": attrs.get("operator",'OR'), "criteria": []}
      if not self.ovalstack: self.ovalstack = [data]
      else:
        self.ovalstack[-1]['criteria'].append(data)
        self.ovalstack.append(data)
    elif name == 'criterion' and self.oval_id:
      self.ovalstack[-1]['criteria'].append({"comment": attrs["comment"],
                                             "oval": attrs["test_ref"]})


  def characters(self, ch):
    if   self.oval_id and self.tag in ['title', 'description', 'status']:
      if self.tag == 'status': ch = ch.lower()
      self.ovals[self.oval_id][self.tag] = ch
    elif self.oval_id and self.tag == 'contributor' and self.data:
      self.data['name'] = ch
    elif self.oval_id and self.tag == 'status_change' and self.data:
      if ch.upper() == "ACCEPTED":
        self.ovals[self.oval_id]['accepted'] = self.data
      self.data = None


  def endElement(self, name):
    self.tag = None
    if   name == 'definition':
      self.oval_id = None
    elif name == 'contributor' and self.oval_id and self.data:
      self.ovals[self.oval_id]['contributors'].append(self.data)
      self.data = None

    #Oval
    elif name == 'criteria' and self.oval_id:
      if   len(self.ovalstack) == 0: return
      elif len(self.ovalstack) == 1:
        self.ovals[self.oval_id]['criteria'] = self.ovalstack.pop()
      else:
        self.ovalstack.pop()


class OVAL(Source):
  def __init__(self):
    self.name = SOURCE_NAME
    parser    = make_parser()
    handler = OVALHandler()
    _file, r = conf.getFeedData(SOURCE_NAME, SOURCE_FILE)
    parser.setContentHandler(handler)
    parser.parse(_file)
    self.cves = {}
    self.oval = handler.ovals

  def updateRefs(self, cveID, cveData):
    if not cveData.get(SOURCE_NAME): cveData[SOURCE_NAME] = []
    for _id in cveData.get('refmap', {}).get('oval', []):
      data = self.oval.get(_id)
      if data: cveData[SOURCE_NAME].append(data)
    if cveData[SOURCE_NAME] == []: cveData.pop(SOURCE_NAME)

  def cleanUp(self, cveID, cveData):
    if cveData.get('refmap', {}).get(SOURCE_NAME):
      del cveData['refmap'][SOURCE_NAME]

  def getSearchables(self):
    return ['id']
