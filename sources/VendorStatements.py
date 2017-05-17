#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Source file for Vendor Statements
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016    Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Sources
SOURCE_NAME = 'statements'
SOURCE_FILE = "https://nvd.nist.gov/download/vendorstatements.xml.gz"

# Imports
from collections     import defaultdict
from xml.sax         import make_parser
from xml.sax.handler import ContentHandler

from lib.Config  import Configuration as conf
from lib.Source  import Source

class VendorStatementsHandler(ContentHandler):
  def __init__(self):
    self.statements = defaultdict(list)
    self.statement  = None
    self.id         = None
    self.tag        = None

  def startElement(self, name, attrs):
    if name == "statement":
      self.statement = {'organization': attrs.get('organization'),
                        'lastmodified': attrs.get('lastmodified'),
                        'contributor':  attrs.get('contributor'),
                        'statement':    ""}
      self.id = attrs.get('cvename')
      self.tag = name

  def characters(self, ch):
    if ch and self.statement and self.id:
      self.statement['statement'] += ch

  def endElement(self, name):
    if self.statement and name == "statement":
      self.statements[self.id].append(self.statement)
      self.statement = None; self.id = None

class VendorStatements(Source):
  def __init__(self):
    self.name = SOURCE_NAME
    parser    = make_parser()
    handler = VendorStatementsHandler()
    _file, r = conf.getFeedData(SOURCE_NAME, SOURCE_FILE)
    parser.setContentHandler(handler)
    parser.parse(_file)
    self.cves = handler.statements

  def getSearchables(self):
    return ['contributor', 'organization']
