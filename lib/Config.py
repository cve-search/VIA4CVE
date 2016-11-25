#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Config reader to read the configuration file
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2013-2014 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014-2016 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# imports
import sys
import os
runPath = os.path.dirname(os.path.realpath(__file__))

import bz2
import configparser
import datetime
import gzip
import re
import urllib.parse
import urllib.request as req
import zipfile
from io import BytesIO

class Configuration():
  ConfigParser = configparser.ConfigParser()
  ConfigParser.read(os.path.join(runPath, "../etc/sources.ini"))
  defaults={'http_proxy': '',
            'd2sec':      "http://www.d2sec.com/exploits/elliot.xml",
            'vendor':     "https://nvd.nist.gov/download/vendorstatements.xml.gz",
            'msbulletin': "http://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx",
            'exploitdb':  "https://github.com/offensive-security/exploit-database/raw/master/files.csv",
            'ref':        "https://cve.mitre.org/data/refs/refmap/allrefmaps.zip",
            'rpm':        "https://www.redhat.com/security/data/metrics/rpm-to-cve.xml",
            'rhsa':       "https://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml.bz2",

            'includemsbulletin': True, 'included2sec':  True, 'includeref': True,
            'includeexploitdb':  True, 'includevendor': True, 'includerpm': True,
            'includerhsa':       True}

  @classmethod
  def readSetting(cls, section, item, default):
    result = default
    try:
      if   type(default) == bool: result = cls.ConfigParser.getboolean(section, item)
      elif type(default) == int:  result = cls.ConfigParser.getint(section, item)
      else:                       result = cls.ConfigParser.get(section, item)
    except:
      pass
    return result

  @classmethod
  def getFeedData(cls, source, unpack=True):
    source = cls.getFeedURL(source)
    return cls.getFile(source, unpack) if source else None

  @classmethod
  def getFeedURL(cls, source):
    return cls.readSetting("Sources", source, cls.defaults.get(source, ""))

  @classmethod
  def includesFeed(cls, feed):
   return cls.readSetting("Enabled Sources", feed, cls.defaults.get('include'+feed, False))

  # Http Proxy
  @classmethod
  def getProxy(cls):
    return cls.readSetting("Proxy", "http", cls.defaults['http_proxy'])

  @classmethod
  def getFile(cls, getfile, unpack=True):
    if cls.getProxy():
      proxy = req.ProxyHandler({'http': cls.getProxy(), 'https': cls.getProxy()})
      auth = req.HTTPBasicAuthHandler()
      opener = req.build_opener(proxy, auth, req.HTTPHandler)
      req.install_opener(opener)
    response = req.urlopen(getfile)
    data = response
    # TODO: if data == text/plain; charset=utf-8, read and decode
    if unpack:
        if   'gzip' in response.info().get('Content-Type'):
          buf = BytesIO(response.read())
          data = gzip.GzipFile(fileobj=buf)
        elif 'bzip2' in response.info().get('Content-Type'):
          data = BytesIO(bz2.decompress(response.read()))
        elif 'zip' in response.info().get('Content-Type'):
          fzip = zipfile.ZipFile(BytesIO(response.read()), 'r')
          if len(fzip.namelist())>0:
            data=BytesIO(fzip.read(fzip.namelist()[0]))
    return (data, response)
