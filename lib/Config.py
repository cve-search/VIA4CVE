#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Config reader to read the configuration file
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

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
            'exitWhenNoSource': True,
            'd2sec':      "http://www.d2sec.com/exploits/elliot.xml",
            'vendor':     "https://nvd.nist.gov/download/vendorstatements.xml.gz",
            'msbulletin': "http://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx"}
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
  def getFeedData(cls, source, default, unpack=True):
    source = cls.readSetting("Sources", source, default)
    return cls.getFile(source, unpack) if source else None

  @classmethod
  def getProxy(cls):
    return cls.readSetting("Proxy", "http", cls.defaults['http_proxy'])

  @classmethod
  def exitWhenNoSource(cls):
    return cls.readSetting("Settings", "exitWhenNoSource", True)

  @classmethod
  def getFile(cls, getfile, unpack=True):
    if cls.getProxy():
      proxy = req.ProxyHandler({'http': cls.getProxy(), 'https': cls.getProxy()})
      auth = req.HTTPBasicAuthHandler()
      opener = req.build_opener(proxy, auth, req.HTTPHandler)
      req.install_opener(opener)
    try:
      response = req.urlopen(getfile)
    except:
      msg = "[!] Could not fetch file %s"%getfile
      if cls.exitWhenNoSource(): sys.exit(msg)
      else:                      print(msg)
      data = None
    data = response.read()
    # TODO: if data == text/plain; charset=utf-8, read and decode
    if unpack:
      if   'gzip' in response.info().get('Content-Type'):
        data = gzip.GzipFile(fileobj = BytesIO(data))
      elif 'bzip2' in response.info().get('Content-Type'):
        data = BytesIO(bz2.decompress(data))
      elif 'zip' in response.info().get('Content-Type'):
        fzip = zipfile.ZipFile(BytesIO(data), 'r')
        if len(fzip.namelist())>0:
          data=BytesIO(fzip.read(fzip.namelist()[0]))
      # In case the webserver is being generic
      elif 'application/octet-stream' in response.info().get('Content-Type'):
        if data[:4] == b'PK\x03\x04': # Zip
          fzip = zipfile.ZipFile(BytesIO(data), 'r')
          if len(fzip.namelist())>0:
            data=BytesIO(fzip.read(fzip.namelist()[0]))
    return (data, response)
