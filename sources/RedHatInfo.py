#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Source file for the RedHat information
#  - RPM
#  - RHSA
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016    Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Sources
SOURCES = {'rhsa': "https://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml.bz2",
           'rpm':  "https://www.redhat.com/security/data/metrics/rpm-to-cve.xml"}

# Imports
import os
import sys

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from collections     import defaultdict
from io              import BytesIO
from xml.sax         import make_parser
from xml.sax.handler import ContentHandler

from lib.Config import Configuration as conf
from lib.Source import Source

def renameOvalStack(stack):
  if type(stack) == dict:
    operator = stack.get('operator')
    criteria = stack.get('criteria')
    if operator and criteria:
      stack[operator] = criteria
      del stack['operator']
      del stack['criteria']
      for item in stack[operator]:
        renameOvalStack(item)
  return stack

##############
# Redhat RPM #
##############
class RPMHandler(ContentHandler):
  def __init__(self):
    self.CVEs = defaultdict(dict)
    self.rpm = None
    self.cveTag = False

  def startElement(self, name, attrs):
    if   name == 'rpm':               self.rpm = attrs.get('rpm')
    elif name == 'cve' and self.rpm:  self.cveTag = True

  def characters(self, ch):
    if self.cveTag:
      if not ('rpms' in self.CVEs[ch.upper()] and
        type(self.CVEs[ch.upper()]['rpms']) is list):
        self.CVEs[ch.upper()]['rpms'] = []
      self.CVEs[ch.upper()]['rpms'].append(self.rpm)

  def endElement(self, name):
    if   name == 'rpm': self.rpm = None
    elif name == 'cve': self.cveTag = False

##############################
# Redhat Security Advisories #
##############################
class RHSAHandler(ContentHandler):
  def __init__(self):
    self.CVEs = defaultdict(dict)
    self.rhsa = None
    self.elem = None
    self.ovalstack = None

  def startElement(self, name, attrs):
    self.elem = name
    if   name == 'definition':  self.rhsa = {'bugzilla': {}, 'rhsa': {}, 'oval': {}}
    elif name == 'issued':      self.rhsa['rhsa']['released'] = attrs.get("date")
    elif name == 'bugzilla':    self.rhsa['bugzilla']['id'] = attrs.get("id")
    elif name == 'reference' and attrs.get("source", "") == "RHSA":
      self.rhsa['rhsa']['id']="-".join(attrs.get("ref_id","").split("-")[:2])
    elif name == 'criteria':
      data = {"operator": attrs["operator"], "criteria": []}
      if not self.ovalstack: self.ovalstack = [data]
      else:
        self.ovalstack[-1]['criteria'].append(data)
        self.ovalstack.append(data)
    elif name == 'criterion':
      self.ovalstack[-1]['criteria'].append({"comment": attrs["comment"],
                                             "oval": attrs["test_ref"]})

  def characters(self, ch):
    if   self.elem in ['title', 'severity']: self.rhsa['rhsa'][self.elem] = ch
    elif self.elem == 'bugzilla':            self.rhsa['bugzilla']['title']=ch
    elif self.elem == 'cve':                 self.rhsa['cve'] = ch

  def endElement(self, name):
    self.elem = None
    if   name == 'definition':
      if 'cve' in self.rhsa:
        cve = self.rhsa.pop("cve")
        if not self.CVEs[cve].get('advisories'):
          self.CVEs[cve]['advisories'] = []
        self.CVEs[cve]['advisories'].append(self.rhsa)
      self.rhsa = None
    elif name == 'criteria':
      if   len(self.ovalstack) == 0: return
      elif len(self.ovalstack) == 1:
        stack = renameOvalStack(self.ovalstack.pop())
        self.rhsa['oval'] = stack
      else:
        self.ovalstack.pop()


class RedHatInfo(Source):
  def __init__(self):
    self.name = "redhat"
    handlers  = [{'handler': RPMHandler(),  'source': 'rpm' },
                 {'handler': RHSAHandler(), 'source': 'rhsa'} ]
    parser    = make_parser()
    self.cves = defaultdict(dict)

    for handler in handlers:
      _file, r = conf.getFeedData(handler['source'],
                                  SOURCES[handler['source']])
      parser.setContentHandler(handler['handler'])
      if type(_file) is bytes:
        _file = BytesIO(_file)
      parser.parse(_file)
      for cve, data in handler['handler'].CVEs.items():
        self.cves[cve].update(data)

  def updateRefs(self, cveID, cveData):
    # See if RHSA IDs are available in refs, and add them to the redhat map
    rhsaIDs = [x.get('rhsa', {}).get('id') for x in cveData.get('redhat', {}).get('advisories', [])]
    for rhsaID in cveData.get('refmap', {}).get('redhat', []):
      if rhsaID not in rhsaIDs:
        if not cveData.get('redhat'): cveData['redhat'] = {'advisories': []}
        if not cveData['redhat'].get('advisories'): cveData['redhat']['advisories'] = []
        cveData['redhat']['advisories'].append({'rhsa': {'id': rhsaID} })

  def cleanUp(self, cveID, cveData):
    if cveData.get('refmap', {}).get('redhat'):
      del cveData['refmap']['redhat']

  def getSearchables(self):
    return ['advisories.rhsa.id', 'advisories.bugzilla.id', 'rpms']
