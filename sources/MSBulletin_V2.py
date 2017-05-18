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
import xlrd
import zipfile
from io import BytesIO

from collections import defaultdict

from lib.Config  import Configuration as conf
from lib.Source  import Source


SOURCE_NAME = "msbulletin.xlsx"
SOURCE_FILE = "https://portal.msrc.microsoft.com/api/security-guidance/en-us/excel"

workbook_format = wf = {'date':             0,  'impact':       6,
                        'bulletin_id':      1,  'title':        2,
                        'knowledgebase_id': 2,  'cves':         4,
                        'severity':     5}

# Convert date "10-jun-17" to datetime "10-01-2017 00:00:00"
def xldate_as_datetime(xldate, datemode):
    date = time.strftime("%d/%m/%Y", time.strptime(xldate,"%d-%b-%y"))
    return datetime.datetime.strptime(date, "%d/%m/%Y")
   
class MSBulletin_V2(Source):
  def __init__(self):
    self.name = SOURCE_NAME
    _file =   conf.get_msbulletin(SOURCE_FILE) # get file xlsx
    workbook  = xlrd.open_workbook(file_contents = _file)
    worksheet = workbook.sheet_by_index(0)
    mskb      = defaultdict(dict)
    self.cves = defaultdict(list)

    for rownum in range(worksheet.nrows-1): # -1 because we skip the header
      row = worksheet.row_values(rownum+1)  # +1 because we skip the header
      # Convert date to date object
      date = xldate_as_datetime(row[wf['date']], 0).isoformat()
      #date = row[wf['date']]
      mskb[row[wf['bulletin_id']]]['date']             = date
      mskb[row[wf['bulletin_id']]]['bulletin_id']      = row[wf['bulletin_id']]
      mskb[row[wf['bulletin_id']]]['knowledgebase_id'] = row[wf['knowledgebase_id']]
      mskb[row[wf['bulletin_id']]]['severity']         = row[wf['severity']]
      mskb[row[wf['bulletin_id']]]['impact']           = row[wf['impact']]
      mskb[row[wf['bulletin_id']]]['title']            = row[wf['title']]
      mskb[row[wf['bulletin_id']]]['cves']             = row[wf['cves']].split(",")

      bulletin_SOURCE_FILE      = worksheet.hyperlink_map.get((rownum, wf['bulletin_id']))
      knowledgebase_SOURCE_FILE = worksheet.hyperlink_map.get((rownum, wf['knowledgebase_id']))
      mskb[row[wf['bulletin_id']]]['bulletin_SOURCE_FILE']      = bulletin_SOURCE_FILE
      mskb[row[wf['bulletin_id']]]['knowledgebase_SOURCE_FILE'] = knowledgebase_SOURCE_FILE

    for _id, data in mskb.items():
      to_store = copy.copy(data)
      to_store.pop("cves")
      for cve in data['cves']:
        if cve: self.cves[cve].append(to_store)

  def cleanUp(self, cveID, cveData):
    if cveData.get('refmap', {}).get('ms'):
      del cveData['refmap']['ms']

  def getSearchables(self):
    return ['bulletin_id', 'knowledgebase_id']