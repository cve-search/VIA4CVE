#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Source file for IAVM information
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016    Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Sources
SOURCE_NAME = 'iavm'
SOURCE_FILE = "http://iasecontent.disa.mil/stigs/xls/iavm-to-cve(u).xls"

# Imports
import xlrd

from collections import defaultdict
from io          import BytesIO

from lib.Config  import Configuration as conf
from lib.Source  import Source

workbook_format = wf = {'vms':          0,
                        'severity':     1,   'date':        6,
                        'release_date': 2,   'cve':         7,
                        'iavm':         3,   'reference':   8,
                        'title':        4,   'url':         9}

class IAVM(Source):
  def __init__(self):
    self.name = SOURCE_NAME
    _file, r = conf.getFeedData(SOURCE_NAME, SOURCE_FILE)
    workbook  = xlrd.open_workbook(file_contents = _file.read())
    worksheet = workbook.sheet_by_index(0)
    iavm      = defaultdict(lambda : {'references': []})
    self.cves = defaultdict(list)

    for rownum in range(worksheet.nrows-1): # -1 because we skip the header
      row = worksheet.row_values(rownum+1)  # +1 because we skip the header
      iavm[row[wf['iavm']]]['iavm']         = row[wf['id']]
      iavm[row[wf['iavm']]]['vms']          = row[wf['vms']]
      iavm[row[wf['iavm']]]['severity']     = row[wf['severity']]
      iavm[row[wf['iavm']]]['release_date'] = row[wf['release_date']]
      iavm[row[wf['iavm']]]['title']        = row[wf['title']]
      iavm[row[wf['iavm']]]['date']         = row[wf['date']]
      if row[wf['cve']]:
        iavm[row[wf['iavm']]]['cve']        = row[wf['cve']]
      if row[wf['url']] and row[wf['reference']]:
        iavm[row[wf['iavm']]]['references'].append({'name': row[wf['reference']],
                                                    'url':  row[wf['url']]})

    for _id, data in iavm.items():
      if data.get('cve'):
        cve = data.pop("cve")
        self.cves[cve] = data
