#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Source file for Microsoft Bulletin information
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016    Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import copy
import datetime
import time
import json
import requests

from collections import defaultdict

from lib.Config  import Configuration as conf
from lib.Source  import Source


SOURCE_NAME = "msbulletin"
SOURCE_FILE = "https://portal.msrc.microsoft.com/api/security-guidance/en-us/"


# Get Ms Bulletins in Json Format
def get_msbulletin(url, from_date= "01/01/1900" , to_Date= None ):
    headers={"Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json;charset=utf-8",
    "Referer": "https://portal.msrc.microsoft.com/en-us/security-guidance"
    }
    query = {
          'familyIds': [], 'productIds': [], 'severityIds': [], 'impactIds': [],
          'pageNumber': 1, 'pageSize': 50000,
          'includeCveNumber':True, 'includeSeverity': True, 'includeImpact': True,
          'orderBy': 'publishedDate', 'orderByMonthly': 'releaseDate',
          'isDescending': True, 'isDescendingMonthly': True,
          'queryText': '', 'isSearch': False, 'filterText': '',
          'fromPublishedDate': from_date
    }

    if to_Date:
      query['toPublishedDate'] = to_date
      
    post = requests.post(url,  headers=headers, data=json.dumps(query) )
    if post:
      return post.json()
    else:
      return None
      
class MSBulletin_V2(Source):
  def __init__(self):
    self.name = SOURCE_NAME
    data_json =   get_msbulletin(SOURCE_FILE) # Get MS Bulletins in Json Format
    mskb      = defaultdict(dict)
    self.cves = defaultdict(list)

    for items in data_json["details"]:  
      mskb[items["knowledgeBaseId"]]['date']             = items["publishedDate"] 
      mskb[items["knowledgeBaseId"]]['kb_id']            = items['knowledgeBaseId'] # KB id
      mskb[items["knowledgeBaseId"]]['knowledgebase_id'] = items['knowledgeBaseId'] # KB id
      mskb[items["knowledgeBaseId"]]['severity']         = items['severity']
      mskb[items["knowledgeBaseId"]]['impact']           = items['impact']
      mskb[items["knowledgeBaseId"]]['title']            = items['name'] # Name of product
      mskb[items["knowledgeBaseId"]]['cves']             = items['cveNumber'] # CVE  id
      mskb[items["knowledgeBaseId"]]['cves_url']         = items['cveUrl']  # CVE url

      mskb[items["knowledgeBaseId"]]['bulletin_SOURCE_FILE']      = SOURCE_FILE
      mskb[items["knowledgeBaseId"]]['knowledgebase_SOURCE_FILE'] = items["knowledgeBaseUrl"]

    for _id, data in mskb.items():
      to_store = copy.copy(data)
      to_store.pop("cves")
      if data['cves']:
          self.cves[data['cves']].append(to_store)

  def cleanUp(self, cveID, cveData):
    if cveData.get('refmap', {}).get('ms'):
      del cveData['refmap']['ms']

  def getSearchables(self):
    return ['kb_id', 'knowledgebase_id']