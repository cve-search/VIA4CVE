#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Source file for Microsoft Bulletin information
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016    Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Sources
SOURCE_NAME = 'msbulletin'
SOURCE_FILE = "https://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx"

# Imports
import copy
import datetime
import xlrd

from collections import defaultdict

from lib.Config  import Configuration as conf
from lib.Source  import Source

workbook_format = wf = {'date':             0,  'impact':       4,
                        'bulletin_id':      1,  'title':        5,
                        'knowledgebase_id': 2,  'cves':        13,
                        'severity':     3}

def minimalist_xldate_as_datetime(xldate, datemode):
    # datemode: 0 for 1900-based, 1 for 1904-based
    return (datetime.datetime(1899, 12, 30)
            + datetime.timedelta(days=xldate + 1462 * datemode))

class MSBulletin(Source):
  def __init__(self):
    self.name = SOURCE_NAME
    _file, r = conf.getFeedData(SOURCE_NAME, SOURCE_FILE, unpack=False) # Don't unpack, 'cuz XLSX's are zips
    workbook  = xlrd.open_workbook(file_contents = _file)
    worksheet = workbook.sheet_by_index(0)
    mskb      = defaultdict(dict)
    self.cves = defaultdict(list)

    for rownum in range(worksheet.nrows-1): # -1 because we skip the header
      row = worksheet.row_values(rownum+1)  # +1 because we skip the header
      # Convert date to date object
      date = minimalist_xldate_as_datetime(row[wf['date']], 0).isoformat()

      mskb[row[wf['bulletin_id']]]['date']             = date
      mskb[row[wf['bulletin_id']]]['bulletin_id']      = row[wf['bulletin_id']]
      mskb[row[wf['bulletin_id']]]['knowledgebase_id'] = row[wf['knowledgebase_id']]
      mskb[row[wf['bulletin_id']]]['severity']         = row[wf['severity']]
      mskb[row[wf['bulletin_id']]]['impact']           = row[wf['impact']]
      mskb[row[wf['bulletin_id']]]['title']            = row[wf['title']]
      mskb[row[wf['bulletin_id']]]['cves']             = row[wf['cves']].split(",")

      bulletin_url      = worksheet.hyperlink_map.get((rownum, wf['bulletin_id']))
      knowledgebase_url = worksheet.hyperlink_map.get((rownum, wf['knowledgebase_id']))
      mskb[row[wf['bulletin_id']]]['bulletin_url']      = bulletin_url
      mskb[row[wf['bulletin_id']]]['knowledgebase_url'] = knowledgebase_url

    for _id, data in mskb.items():
      to_store = copy.copy(data)
      to_store.pop("cves")
      for cve in data['cves']:
        if cve: self.cves[cve].append(to_store)

  def cleanUp(self, cveID, cveData):
    if cveData.get('refmap', {}).get('ms'):
      del cveData['refmap']['ms']
