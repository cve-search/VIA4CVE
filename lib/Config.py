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

import requests

class Configuration():
  ConfigParser = configparser.ConfigParser()
  ConfigParser.read(os.path.join(runPath, "../etc/configuration.ini"))
  defaults={'http_proxy': '', 'exitWhenNoSource': True}
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
  
  # Get Microsoft Bulletin
  def get_msbulletin(url):
    h1={"Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json;charset=utf-8",
    "Referer": "https://portal.msrc.microsoft.com/en-us/security-guidance"
    }
    data1 ='{"familyIds":[],"productIds":[],"severityIds":[],"impactIds":[],"pageNumber":1,"pageSize":100,"includeCveNumber":true,"includeSeverity":true,"includeImpact":true,"orderBy":"publishedDate","orderByMonthly":"releaseDate","isDescending":true,"isDescendingMonthly":true,"queryText":"","isSearch":false,"filterText":"","fromPublishedDate":"04/12/2017","toPublishedDate":"05/17/2017"}'
    post = requests.post(url,  headers=h1, data=data1)
    data=b''
    for chunk in post.iter_content(chunk_size=128):
        data=data+chunk
    if len(data)>0:
      return data
    else:
      return None